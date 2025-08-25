#!/bin/bash
echo "Installing FRP Web-UI" && 
mkdir -p /root/frp/Source /root/frp/templates && 
cd /root/frp && 
git clone https://github.com/md9786/FRP-Management-Webui.git && 
cd FRP-Management-Webui && 
git checkout 8d7019f96cf26a0079700a96171b539453533ff7 && 
cp frp_ui /root/frp/ && 
cp Source/EFRP.sh /root/frp/Source/ && 
cp -r Source/templates/* /root/frp/templates/ && 
cd .. && 
rm -rf FRP-Management-Webui && 
chmod +x /root/frp/frp-ui && 
chmod +x /root/frp/EFRP.sh && 
echo "[Unit]
Description=FRP Web UI
After=network.target

[Service]
User=root
WorkingDirectory=/root/frp
ExecStart=/root/frp/frp-ui
Restart=always

[Install]
WantedBy=multi-user.target

[Service]
ExecStart=/root/frp/EFRP.sh
Restart=always
User=root

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/EFRP.service && 
systemctl stop frp_ui.service 2>/dev/null || true && 
systemctl disable frp_ui.service 2>/dev/null || true && 
systemctl daemon-reload && 
systemctl enable frp_ui.service && 
systemctl start frp_ui.service && 
systemctl enable EFRP.service && 
systemctl start EFRP.service && 
ip=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v "127.0.0.1" | head -n 1) && 
echo "FRP Web-UI installed, you can access it using http://$ip:5000
