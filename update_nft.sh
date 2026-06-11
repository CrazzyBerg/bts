#!/bin/bash

WAN_IF=$(ip route | awk '/default/ {print $5; exit}')

sudo sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf && sudo sysctl -p

sudo nft flush ruleset
sudo tee /etc/nftables.conf > /dev/null <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table ip nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IF" masquerade
    }
}
EOF

sudo nft -f /etc/nftables.conf
sudo systemctl enable nftables
sudo systemctl restart nftables