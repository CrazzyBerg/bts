#!/bin/bash

# Define the service file path
SERVICE_FILE="/etc/systemd/system/yate.service"

# Create the yate service file
echo "[Unit]
Description=Yate
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/yate
Restart=on-failure
StandardOutput=journal
StandardError=append:/var/log/yate.err

[Install]
WantedBy=multi-user.target" | sudo tee $SERVICE_FILE > /dev/null

# Create the log files
sudo touch /var/log/yate.err
sudo chmod 644 /var/log/yate.err

# Reload systemd manager configuration
sudo systemctl daemon-reload

# Ask the user if they want to enable the service on boot
read -p "Do you want to enable the Yate service to start on boot? (y/n): " enable_on_boot

if [[ "$enable_on_boot" =~ ^[Yy]$ ]]; then
    sudo systemctl enable yate.service
    echo "Yate service will start on boot."
fi
