#!/bin/bash

# --- Configuration ---
CONFIG_DIR="/root/frp/client" # Directory containing FRP client configuration files
ERROR_STRING="connect to server error: timeout|connect to local service error: dial tcp" # Partial string to look for in logs
LOG_FILE="/var/log/frp_monitor.log" # Log file for this script's actions
MAX_RESTARTS_IN_ROW=3 # Maximum consecutive restarts per service before waiting
CHECK_INTERVAL_SECONDS=10 # How often to check logs for errors (in seconds)
SCHEDULED_RESTART_INTERVAL_MINUTES=20 # How often to perform a scheduled restart (in minutes)
RESTART_STABILIZE_SLEEP=3 # Time to wait after a restart for service to stabilize
RESTART_WAIT_SECONDS=10 # Time to wait after reaching max restarts before trying again# --- Functions ---

# Function to log messages with a timestamp
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
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
        return 0 # Success
    else
        log_message "Failed to restart frpc@$service_name.service. Check systemctl status. Error code: $?."
        return 1 # Failure
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
for config_file in "$CONFIG_DIR"/*.toml; do
    if [ ! -e "$config_file" ]; then
        log_message "Error: No .toml configuration files found in $CONFIG_DIR. Exiting."
        echo "Error: No .toml configuration files found in $CONFIG_DIR. Exiting."
        exit 1
    fi
    client_name=$(basename "$config_file" .toml)
    service_name="$client_name"
    restart_counts["$service_name"]=0
done

last_scheduled_restart_time=$(date +%s) # Initialize with current time in seconds since epoch

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
        last_scheduled_restart_time=$current_time # Update last scheduled restart time    fi

    # Check each service for errors
    for config_file in "$CONFIG_DIR"/*.toml; do
        if [ ! -e "$config_file" ]; then
            log_message "Error: No .toml configuration files found in $CONFIG_DIR. Skipping error check."
            continue
        fi
        client_name=$(basename "$config_file" .toml)
        service_name="$client_name"
        log_message "Checking for error string: '$ERROR_STRING' in frpc@$service_name.service logs..."

        # Use journalctl to get the last few lines of the service log
        if journalctl -u "frpc@$service_name.service" --no-pager -n 3 | grep -E "$ERROR_STRING"; then
            log_message "ERROR '$ERROR_STRING' DETECTED in frpc@$service_name.service logs!"

            if [ "${restart_counts["$service_name"]}" -ge "$MAX_RESTARTS_IN_ROW" ]; then
                log_message "Maximum consecutive error-based restarts ($MAX_RESTARTS_IN_ROW) reached for frpc@$service_name.service. Waiting $RESTART_WAIT_SECONDS seconds before retrying."
                sleep "$RESTART_WAIT_SECONDS"
                restart_counts["$service_name"]=0 # Reset restart count to allow retry            fi

            restart_counts["$service_name"]=$((restart_counts["$service_name"] + 1))
            log_message "Error-based restart attempt #${restart_counts["$service_name"]} for frpc@$service_name.service."

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

    # Wait before the next check for errors
    sleep "$CHECK_INTERVAL_SECONDS"
done