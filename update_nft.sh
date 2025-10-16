#!/bin/bash

sudo sed -i 's/^#*net.ipv4.ip_forward=.*/net.ipv4.ip_forward=1/' /etc/sysctl.conf && sudo sysctl -p

sudo nft flush ruleset
sudo nft add table ip nat
sudo nft add chain ip nat postrouting '{ type nat hook postrouting priority srcnat; policy accept; }'
sudo nft add rule ip nat postrouting oifname "eth0" masquerade

sudo nft list ruleset | sudo tee /etc/nftables.conf > /dev/null