#!/bin/bash

# --- Configuration ---
CONFIG_DIR="/root/frp/client" # Directory containing FRP client configuration files
ERROR_STRING="connect to server error: dial tcp |connect to server error: timeout|connect to local service.*error: dial tcp.*connection refused" # Updated error string pattern
LOG_FILE="/var/log/frp_monitor.log" # Log file for this script's actions
MAX_RESTARTS_IN_ROW=3 # Maximum consecutive restarts per service before waiting
CHECK_INTERVAL_SECONDS=10 # How often to check logs for errors (in seconds)
AGGRESSIVE_RESTART_INTERVAL_MINUTES=20 # Aggressive restart every 20 minutes (TCP RST)
DAILY_GRACEFUL_HOUR=5 # Hour (0-23) for daily graceful restart (~5:00 AM)
RESTART_STABILIZE_SLEEP=3 # Time to wait after a restart for service to stabilize
RESTART_WAIT_SECONDS=10 # Time to wait after reaching max restarts before trying again

# --- Failover settings ---
PRIMARY_DOMAIN="your_domestic_domain"        # main domain (matches your template)
SECONDARY_DOMAIN="your_backup_domestic_domain"    # set your secondary domain here
FAILOVER_AFTER_RESTARTS=2                   # switch to secondary after this many consecutive error-based restarts on a service
PRIMARY_RECHECK_MINUTES=10                  # probe primary every N minutes while on secondary

STATE_DIR="/var/lib/frp-monitor"
mkdir -p "$STATE_DIR"
failover_flag_file="$STATE_DIR/failover_enabled.flag"

# --- Functions ---

# Function to log messages with a timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to check if a service is active
check_service_status() {
    local service_name="$1"
    if systemctl is-active --quiet "frpc@$service_name.service"; then
        return 0 # Service is active
    else
        return 1 # Service is not active
    fi
}

# Function to stop all FRP services (graceful: FIN packets)
graceful_stop_all() {
    log_message "Performing graceful stop of all frpc services (systemctl stop → clean FIN)."
    for config_file in "$CONFIG_DIR"/*.toml; do
        [ -e "$config_file" ] || continue
        local svc="$(basename "$config_file" .toml)"
        sudo systemctl stop "frpc@$svc.service"
    done
    # Short sleep to allow connections to close cleanly
    sleep 5
}

# Function to start all FRP services
start_all_services() {
    log_message "Starting all frpc services."
    for config_file in "$CONFIG_DIR"/*.toml; do
        [ -e "$config_file" ] || continue
        local svc="$(basename "$config_file" .toml)"
        sudo systemctl start "frpc@$svc.service"
        sleep "$RESTART_STABILIZE_SLEEP"
        if check_service_status "$svc"; then
            log_message "frpc@$svc.service started successfully."
        else
            log_message "frpc@$svc.service failed to start."
        fi
    done
}

# Function to aggressively restart a specific service (kill -9 → TCP RST)
aggressive_restart_service() {
    local service_name="$1"
    log_message "Aggressive restart (kill -9 → TCP RST) of frpc@$service_name.service."

    # Find PIDs of the frpc process for this instance
    local pids=$(pgrep -f "frpc.*-c ${CONFIG_DIR}/${service_name}.toml")
    if [ -n "$pids" ]; then
        log_message "Killing frpc processes (PIDs: $pids) with SIGKILL for instant RST."
        kill -9 $pids 2>/dev/null || true
    fi

    # Also ensure systemd knows the service is down
    sudo systemctl stop "frpc@$service_name.service" 2>/dev/null || true

    # Now start it again
    sudo systemctl start "frpc@$service_name.service"
    sleep "$RESTART_STABILIZE_SLEEP"
    if check_service_status "$service_name"; then
        log_message "frpc@$service_name.service aggressively restarted and is active."
        return 0
    else
        log_message "frpc@$service_name.service failed to become active after aggressive restart."
        return 1
    fi
}

# Function to aggressively restart ALL services
aggressive_restart_all() {
    log_message "Performing aggressive restart of ALL frpc services (TCP RST)."
    for config_file in "$CONFIG_DIR"/*.toml; do
        [ -e "$config_file" ] || continue
        local svc="$(basename "$config_file" .toml)"
        aggressive_restart_service "$svc"
    done
}

# --- New helper functions for domain switching (unchanged) ---

# Safely replace serverAddr in all configs to the provided domain
set_domain_all_configs() {
  local new_domain="$1"
  log_message "Setting serverAddr to ${new_domain} in all configs"
  for f in "$CONFIG_DIR"/*.toml; do
    if [ -f "$f" ]; then
        sed -i.bak -E "s|^(serverAddr[[:space:]]*=[[:space:]]*\").*(\")|\1${new_domain}\2|g" "$f"
    fi
  done
}

# Validate configs if frpc has a verify command (optional safety)
validate_configs_or_revert() {
  if command -v frpc >/dev/null 2>&1; then
    local ok=0
    for f in "$CONFIG_DIR"/*.toml; do
      if [ -f "$f" ]; then
          if ! frpc verify -c "$f" >/dev/null 2>&1; then
            log_message "Validation failed for $f, restoring from .bak"
            cp -f "$f.bak" "$f"
            ok=1
          fi
      fi
    done
    return $ok
  fi
  return 0
}

# Restart all frpc@*.services aggressively (used after domain switch)
restart_all_services() {
  aggressive_restart_all
}

# Enable failover to SECONDARY_DOMAIN
enable_failover() {
  if [ -f "$failover_flag_file" ]; then
    log_message "Failover already active; skipping switch."
    return 0
  fi
  set_domain_all_configs "$SECONDARY_DOMAIN"
  if ! validate_configs_or_revert; then
    log_message "Failover validation failed; not switching domains."
    return 1
  fi
  touch "$failover_flag_file"
  log_message "Failover enabled; switched all configs to secondary domain."
  restart_all_services
  return 0
}

# Disable failover and switch back to PRIMARY_DOMAIN
disable_failover() {
  if [ ! -f "$failover_flag_file" ]; then
    log_message "Failover not active; skipping revert."
    return 0
  fi
  set_domain_all_configs "$PRIMARY_DOMAIN"
  if ! validate_configs_or_revert; then
    log_message "Primary validation failed; staying on secondary."
    return 1
  fi
  rm -f "$failover_flag_file"
  log_message "Failover disabled; switched all configs back to primary domain."
  restart_all_services
  return 0
}

# Probe primary domain health (unchanged except restart uses aggressive mode)
probe_primary_health() {
  local probe_cfg=""
  for f in "$CONFIG_DIR"/*.toml; do
    if [ -f "$f" ]; then
        probe_cfg="$f"
        break
    fi
  done
  
  [ -n "$probe_cfg" ] || return 1
  local probe_svc="$(basename "$probe_cfg" .toml)"

  cp -f "$probe_cfg" "$probe_cfg.probe.bak"
  sed -i -E "s|^(serverAddr[[:space:]]*=[[:space:]]*\").*(\")|\1${PRIMARY_DOMAIN}\2|g" "$probe_cfg"
  
  if command -v frpc >/dev/null 2>&1; then
    if ! frpc verify -c "$probe_cfg" >/dev/null 2>&1; then
      log_message "Probe config validation failed; reverting probe file."
      cp -f "$probe_cfg.probe.bak" "$probe_cfg"
      rm -f "$probe_cfg.probe.bak"
      return 1
    fi
  fi

  aggressive_restart_service "$probe_svc"

  local err
  err=$(journalctl -u "frpc@$probe_svc.service" --since "2 minutes ago" --no-pager | grep -E "$ERROR_STRING")
  local ok=$?

  cp -f "$probe_cfg.probe.bak" "$probe_cfg"
  rm -f "$probe_cfg.probe.bak"
  
  if [ $ok -eq 0 ]; then
     aggressive_restart_service "$probe_svc"
     log_message "Primary probe detected errors; primary still unhealthy."
     return 1
  else
     log_message "Primary probe shows healthy; primary appears good."
     return 0
  fi
}

# --- Main Script Logic ---

if ! touch "$LOG_FILE" 2>/dev/null; then
    echo "Error: Cannot create or write to log file: $LOG_FILE. Exiting."
    exit 1
fi

log_message "Starting monitoring and restart script for FRP services..."

if [ ! -d "$CONFIG_DIR" ]; then
    log_message "Error: Configuration directory $CONFIG_DIR not found! Exiting."
    echo "Error: Configuration directory $CONFIG_DIR not found! Exiting."
    exit 1
fi

declare -A restart_counts
config_files_found=false
for config_file in "$CONFIG_DIR"/*.toml; do
    if [ -e "$config_file" ]; then
        config_files_found=true
        client_name=$(basename "$config_file" .toml)
        service_name="$client_name"
        restart_counts["$service_name"]=0
        log_message "Found configuration for service: frpc@$service_name.service"
    fi
done

if [ "$config_files_found" = false ]; then
    log_message "Error: No .toml configuration files found in $CONFIG_DIR. Exiting."
    echo "Error: No .toml configuration files found in $CONFIG_DIR. Exiting."
    exit 1
fi

last_aggressive_restart_time=$(date +%s)
last_daily_graceful_done=$(date +%s)
last_primary_probe_time=0

# For daily graceful: track if we already did it today
today=$(date +%Y-%m-%d)
daily_graceful_done=false

while true; do
    current_time=$(date +%s)
    current_hour=$(date +%H)
    current_date=$(date +%Y-%m-%d)

    # Daily graceful restart at ~5:00 AM (only once per day)
    if [ "$current_date" != "$today" ]; then
        # New day started
        today="$current_date"
        daily_graceful_done=false
    fi

    if [ "$daily_graceful_done" = false ] && [ "$current_hour" -ge "$DAILY_GRACEFUL_HOUR" ]; then
        log_message "Performing daily graceful restart (clean FIN) at ~${DAILY_GRACEFUL_HOUR}:00."
        graceful_stop_all
        start_all_services
        # Reset all error-based counters after graceful restart
        for svc in "${!restart_counts[@]}"; do
            restart_counts["$svc"]=0
        done
        daily_graceful_done=true
    fi

    # Aggressive restart every 20 minutes
    if (( current_time - last_aggressive_restart_time >= AGGRESSIVE_RESTART_INTERVAL_MINUTES * 60 )); then
        log_message "Performing scheduled aggressive restart (every $AGGRESSIVE_RESTART_INTERVAL_MINUTES minutes → TCP RST)."
        aggressive_restart_all
        # Reset error-based counters after aggressive restart
        for svc in "${!restart_counts[@]}"; do
            restart_counts["$svc"]=0
        done
        last_aggressive_restart_time=$current_time
    fi

    # Check each service for errors → use aggressive restart on error
    for config_file in "$CONFIG_DIR"/*.toml; do
        [ -e "$config_file" ] || continue
        client_name=$(basename "$config_file" .toml)
        service_name="$client_name"
        log_message "Checking logs for frpc@$service_name.service..."

        error_output=$(journalctl -u "frpc@$service_name.service" --no-pager -n 5 | grep -E "$ERROR_STRING")
        if [ -n "$error_output" ]; then
            log_message "ERROR DETECTED in frpc@$service_name.service: $error_output"

            if [ "${restart_counts["$service_name"]}" -ge "$MAX_RESTARTS_IN_ROW" ]; then
                log_message "Max consecutive restarts reached for $service_name. Waiting $RESTART_WAIT_SECONDS seconds."
                sleep "$RESTART_WAIT_SECONDS"
                restart_counts["$service_name"]=0
            fi

            restart_counts["$service_name"]=$((restart_counts["$service_name"] + 1))
            log_message "Error-based aggressive restart #${restart_counts["$service_name"]} for frpc@$service_name.service."

            if [ ! -f "$failover_flag_file" ] && [ "${restart_counts["$service_name"]}" -ge "$FAILOVER_AFTER_RESTARTS" ]; then
                log_message "Failover threshold reached on $service_name; switching to secondary domain."
                if enable_failover; then
                  last_primary_probe_time=$(date +%s)
                fi
            fi

            aggressive_restart_service "$service_name"
        else
            if [ "${restart_counts["$service_name"]}" -gt 0 ]; then
                log_message "No recent error for $service_name; resetting counter."
            fi
            restart_counts["$service_name"]=0
        fi
    done

    # Periodic primary probe while in failover
    if [ -f "$failover_flag_file" ]; then
      now=$(date +%s)
      if (( now - last_primary_probe_time >= PRIMARY_RECHECK_MINUTES * 60 )); then
        log_message "Probing primary domain health while on secondary."
        if probe_primary_health; then
          disable_failover
        else
          log_message "Primary still unhealthy; remaining on secondary."
        fi
        last_primary_probe_time=$now
      fi
    fi

    sleep "$CHECK_INTERVAL_SECONDS"
done