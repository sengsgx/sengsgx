#!/bin/bash
IPERF="https://github.com/esnet/iperf/archive/3.1.3.tar.gz"
CURL="https://github.com/curl/curl/releases/download/curl-7_47_0/curl-7.47.0.tar.bz2"
NGINX="https://nginx.org/download/nginx-1.10.3.tar.gz"

WRK2="https://github.com/giltene/wrk2/archive/e0109df5b9de09251adb5f5848f223fbee2aa9f5.zip"

FILES=("$IPERF" "$CURL" "$NGINX" "$WRK2")

for f in ${FILES[@]}
do
        wget "$f"
done

# note: we use the apt version of telnet, which is already installed by the base container
#sudo apt install telnet

