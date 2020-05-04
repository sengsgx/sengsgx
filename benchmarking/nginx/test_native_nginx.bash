#!/bin/bash
BIN=~/benchmarking/nginx-1.10.3/build/sbin/nginx
ulimit -n 512
sudo nice -n -20 ${BIN} -c conf/nginx_pure_and_native.conf
