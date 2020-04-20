#!/bin/bash
sudo ip link set tunFA down || exit 1
sudo ip tuntap delete mode tun name tunFA || exit 1
