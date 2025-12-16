#!/bin/bash

# --- Configuration ---
CONFIG_DIR="/root/frp/client" # Directory containing FRP client configuration files
ERROR_STRING="connect to server error: dial tcp |connect to server error: timeout|connect to local service.*error: dial tcp.*connection refused" # Updated error string pattern
LOG_FILE="/var/log/frp_monitor.log" # Log file for this script's actions
MAX_RESTARTS_IN_ROW=3 # Maximum consecutive restarts per service before waiting
CHECK_INTERVAL_SECONDS=10 # How often to check logs for errors (in seconds)
SCHEDULED_RESTART_INTERVAL_MINUTES=20 # How often to perform a scheduled restart (in minutes)
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

# Function to restart a specific FRP service
restart_frp_service() {
    local service_name="$1"
    log_message "Initiating restart of frpc@$service_name.service."

    # Restart the FRP service
    log_message "Restarting frpc@$service_name.service."
    sudo systemctl restart "frpc@$service_name.service"
    if [ $? -eq 0 ]; then
        log_message "frpc@$service_name.service restarted successfully."
        sleep "$RESTART_STABILIZE_SLEEP" # Give service time to start and log
        if check_service_status "$service_name"; then
            log_message "frpc@$service_name.service is active after restart."
            return 0 # Success
        else
            log_message "frpc@$service_name.service is not active after restart. Check systemctl status."
            return 1 # Failure
        fi
    else
        log_message "Failed to restart frpc@$service_name.service. Error code: $?."
        return 1 # Failure
    fi
}

# --- New helper functions for domain switching ---

# Safely replace serverAddr in all configs to the provided domain
set_domain_all_configs() {
  local new_domain="$1"
  log_message "Setting serverAddr to ${new_domain} in all configs"
  # Create .bak backups; anchor to serverAddr key
  sed -i.bak -E "s|^(serverAddr[[:space:]]*=[[:space:]]*\").*(\")|\1${new_domain}\2|g" "$CONFIG_DIR"/*.toml
}

# Validate configs if frpc has a verify command (optional safety)
validate_configs_or_revert() {
  if command -v frpc >/dev/null 2>&1; then
    local ok=0
    for f in "$CONFIG_DIR"/*.toml; do
      if ! frpc verify -c "$f" >/dev/null 2>&1; then
        log_message "Validation failed for $f, restoring from .bak"
        cp -f "$f.bak" "$f"
        ok=1
      fi
    done
    return $ok
  fi
  return 0
}

# Restart all frpc@*.services
restart_all_services() {
  for config_file in "$CONFIG_DIR"/*.toml; do
    [ -e "$config_file" ] || continue
    local svc="$(basename "$config_file" .toml)"
    restart_frp_service "$svc"
  done
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

# Probe primary domain health: temporarily switch one service to PRIMARY, restart it, and check logs
probe_primary_health() {
  # Pick the first config as probe
  local probe_cfg
  probe_cfg="$(ls "$CONFIG_DIR"/*.toml 2>/dev/null | head -n1)"
  [ -n "$probe_cfg" ] || return 1
  local probe_svc="$(basename "$probe_cfg" .toml)"

  # Backup and switch only this file to PRIMARY
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

  # Restart the probe service
  restart_frp_service "$probe_svc"

  # Check for recent errors in the last 2 minutes
  local err
  err=$(journalctl -u "frpc@$probe_svc.service" --since "2 minutes ago" --no-pager | grep -E "$ERROR_STRING")
  local ok=$?

  # Revert probe file to original state
  cp -f "$probe_cfg.probe.bak" "$probe_cfg"
  rm -f "$probe_cfg.probe.bak"

  if [ $ok -eq 0 ]; then
    log_message "Primary probe detected errors; primary still unhealthy."
    return 1
  else
    log_message "Primary probe shows healthy; primary appears good."
    return 0
  fi
}

# --- Main Script Logic ---

# Ensure log file exists and is writable
if ! touch "$LOG_FILE" 2>/dev/null; then
    echo "Error: Cannot create or write to log file: $LOG_FILE. Exiting."
    exit 1
fi

log_message "Starting monitoring and restart script for FRP services..."

# Check if configuration directory exists
if [ ! -d "$CONFIG_DIR" ]; then
    log_message "Error: Configuration directory $CONFIG_DIR not found! Exiting."
    echo "Error: Configuration directory $CONFIG_DIR not found! Exiting."
    exit 1
fi

# Initialize restart counts for each service based on config files
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

last_scheduled_restart_time=$(date +%s) # Initialize with current time in seconds since epoch
last_primary_probe_time=0               # for periodic primary checks when in failover

while true; do
    current_time=$(date +%s)
    
    # Check for scheduled restart
    if (( current_time - last_scheduled_restart_time >= SCHEDULED_RESTART_INTERVAL_MINUTES * 60 )); then
        log_message "Performing scheduled restart (every $SCHEDULED_RESTART_INTERVAL_MINUTES minutes)."
        for config_file in "$CONFIG_DIR"/*.toml; do
            if [ ! -e "$config_file" ]; then
                log_message "Error: No .toml configuration files found in $CONFIG_DIR. Skipping scheduled restart."
                continue
            fi
            client_name=$(basename "$config_file" .toml)
            service_name="$client_name"
            restart_frp_service "$service_name"
            if [ $? -ne 0 ]; then
                log_message "Scheduled restart failed for frpc@$service_name.service. Script will continue to monitor."
            fi
            restart_counts["$service_name"]=0 # Reset error-based restart count after a scheduled restart
        done
        last_scheduled_restart_time=$current_time # Update last scheduled restart time
    fi

    # Check each service for errors
    for config_file in "$CONFIG_DIR"/*.toml; do
        if [ ! -e "$config_file" ]; then
            log_message "Error: No .toml configuration files found in $CONFIG_DIR. Skipping error check."
            continue
        fi
        client_name=$(basename "$config_file" .toml)
        service_name="$client_name"
        log_message "Checking for error string: '$ERROR_STRING' in frpc@$service_name.service logs..."

        # Use journalctl to get the last few lines of the service log and capture any error
        error_output=$(journalctl -u "frpc@$service_name.service" --no-pager -n 5 | grep -E "$ERROR_STRING")
        if [ -n "$error_output" ]; then
            log_message "ERROR DETECTED in frpc@$service_name.service logs: $error_output"

            if [ "${restart_counts["$service_name"]}" -ge "$MAX_RESTARTS_IN_ROW" ]; then
                log_message "Maximum consecutive error-based restarts ($MAX_RESTARTS_IN_ROW) reached for frpc@$service_name.service. Waiting $RESTART_WAIT_SECONDS seconds before retrying."
                sleep "$RESTART_WAIT_SECONDS"
                restart_counts["$service_name"]=0 # Reset restart count to allow retry
            fi

            restart_counts["$service_name"]=$((restart_counts["$service_name"] + 1))
            log_message "Error-based restart attempt #${restart_counts["$service_name"]} for frpc@$service_name.service."

            # If failover not active and threshold reached, switch all configs to secondary
            if [ ! -f "$failover_flag_file" ] && [ "${restart_counts["$service_name"]}" -ge "$FAILOVER_AFTER_RESTARTS" ]; then
                log_message "Threshold reached on $service_name; enabling failover to secondary domain."
                if enable_failover; then
                  last_primary_probe_time=$(date +%s)
                fi
            fi

            # Call the restart function
            restart_frp_service "$service_name"
            if [ $? -ne 0 ]; then
                log_message "Error-based restart failed for frpc@$service_name.service. Continuing to monitor other services."
            fi
        else
            # If no error detected, reset the error-based restart counter for this service
            if [ "${restart_counts["$service_name"]}" -gt 0 ]; then
                log_message "No error detected in the last check for frpc@$service_name.service. Resetting consecutive error-based restart count."
            fi
            restart_counts["$service_name"]=0
            log_message "No error detected. frpc@$service_name.service appears to be running normally."
        fi
    done

    # While in failover, periodically probe primary and revert if healthy
    if [ -f "$failover_flag_file" ]; then
      now=$(date +%s)
      if (( now - last_primary_probe_time >= PRIMARY_RECHECK_MINUTES * 60 )); then
        log_message "Probing primary domain availability."
        if probe_primary_health; then
          disable_failover
        else
          log_message "Primary still unhealthy; staying on secondary."
        fi
        last_primary_probe_time=$now
      fi
    fi

    # Wait before the next check for errors
    sleep "$CHECK_INTERVAL_SECONDS"
done
