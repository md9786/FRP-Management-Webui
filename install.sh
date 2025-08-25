#!/bin/bash
echo "Installing FRP Web-UI" && mkdir -p /root/frp && cd /root/frp && wget -O frp-ui https://raw.githubusercontent.com/md9786/FRP-Management-Webui/refs/heads/main/frp_ui && chmod +x frp-ui && echo "[Unit]
Description=FRP Web UI
After=network.target

[Service]
User=root
WorkingDirectory=/root/frp
ExecStart=/root/frp/frp-ui
Restart=always

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/frp_ui.service && systemctl stop frp_ui.service 2>/dev/null || true && systemctl disable frp_ui.service 2>/dev/null || true && systemctl daemon-reload && systemctl enable frp_ui.service && systemctl start frp_ui.service && ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1) && echo "FRP Web-UI installed, you can access it using http://$ip:5001"
