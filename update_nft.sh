#!/bin/bash

sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -p

sudo nft add table ip nat
sudo nft add chain ip nat postrouting { type nat hook postrouting priority srcnat; policy accept; }
sudo nft add rule ip nat postrouting oifname "eth0" masquerade

sudo nft list ruleset > /etc/nftables.conf
sudo systemctl enable nftables
sudo systemctl restart nftables