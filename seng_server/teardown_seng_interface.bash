#!/bin/bash
sudo ip link set tunFA down || exit 1
sudo ip tuntap delete mode tun name tunFA || exit 1

# TODO: in the following rules, change "eno1" to your interface name(s)

# FORWARDing
#sudo iptables -D FORWARD -i tunFA -o eno1 --src 192.168.28.0/24 -j ACCEPT
#sudo iptables -D FORWARD -i tunFA -o eno1 --src 172.16.28.0/24 -j ACCEPT
#sudo iptables -D FORWARD -i eno1 -o tunFA --dst 192.168.28.0/24 -j ACCEPT
#sudo iptables -D FORWARD -i eno1 -o tunFA --dst 172.16.28.0/24 -j ACCEPT

# NAT
#sudo iptables -t nat -D POSTROUTING --src 192.168.28.0/24 -o eno1 -j MASQUERADE
#sudo iptables -t nat -D POSTROUTING --src 172.16.28.0/24 -o eno1 -j MASQUERADE
