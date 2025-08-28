#!/bin/bash
set -e  # Exit on any error
set -x  # Enable debug output

echo "Installing FRP Web-UI"

# Create directories
mkdir -p  /root/frp/frp-ui/templates || { echo "Failed to create directories"; exit 1; }
cd /root/frp || { echo "Failed to change to /root/frp"; exit 1; }

# Clone repository
if ! git clone https://github.com/md9786/FRP-Management-Webui.git; then
    echo "Failed to clone repository"
    exit 1
fi

cd FRP-Management-Webui || { echo "Failed to change to FRP-Management-Webui"; exit 1; }

# Copy files
cp frp-ui /root/frp/frp-ui/ || { echo "Failed to copy frp-ui"; exit 1; }
cp Source/EFRP.sh /root/frp/frp-ui/ || { echo "Failed to copy EFRP.sh"; exit 1; }
cp -r Source/templates/* /root/frp/frp-ui/templates/ || { echo "Failed to copy templates"; exit 1; }

# Clean up
cd .. || { echo "Failed to change directory"; exit 1; }
rm -rf FRP-Management-Webui || { echo "Failed to remove source folder"; exit 1; }

# Set permissions
chmod +x /root/frp/frp-ui/frp-ui || { echo "Failed to set permissions for frp-ui"; exit 1; }
chmod +x /root/frp/frp-ui/EFRP.sh || { echo "Failed to set permissions for EFRP.sh"; exit 1; }

# Create systemd files
cat > /etc/systemd/system/frp-ui.service << EOF || { echo "Failed to create frp-ui.service"; exit 1; }
[Unit]
Description=FRP Web UI
After=network.target

[Service]
User=root
WorkingDirectory=/root/frp/frp-ui/
ExecStart=/root/frp/frp-ui/frp-ui
Restart=always

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/EFRP.service << EOF || { echo "Failed to create EFRP.service"; exit 1; }
[Unit]
Description=EFRP Service
After=network.target

[Service]
User=root
WorkingDirectory=/root/frp/frp-ui/
ExecStart=/root/frp/frp-ui/EFRP.sh
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Manage services
systemctl stop frp-ui.service 2>/dev/null || true
systemctl disable frp-ui.service 2>/dev/null || true
systemctl daemon-reload || { echo "Failed to reload systemd"; exit 1; }
systemctl enable frp-ui.service || { echo "Failed to enable frp-ui.service"; exit 1; }
systemctl start frp-ui.service || { echo "Failed to start frp-ui.service"; exit 1; }
systemctl enable EFRP.service || { echo "Failed to enable EFRP.service"; exit 1; }
systemctl start EFRP.service || { echo "Failed to start EFRP.service"; exit 1; }

# Get IP address
ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1) || { echo "Failed to get IP address"; exit 1; }
echo "FRP Web-UI installed, you can access it using http://$ip:5000"
echo "FRP Web-UI installed, you can access it using admin:admin"
