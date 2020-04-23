#!/bin/bash
IPERF="3.1.3"
CURL="curl-7.47.0"
NGINX="nginx-1.10.3"

WRK2="e0109df5b9de09251adb5f5848f223fbee2aa9f5"

# iPerf3
echo "Preparing iPerf3"
gunzip ${IPERF}.tar.gz && tar xvf ${IPERF}.tar || exit 1
pushd iperf-${IPERF}

echo "Patching and configuring iPerf3"
patch -p1 < ../patches/iperf-3.1.3_close_sockets.patch || exit 1
./configure --prefix=`pwd`/build/ --without-openssl \
        iperf3_cv_header_so_max_pacing_rate=false \
        iperf3_cv_header_tcp_congestion=false \
        ac_cv_func_sendfile=no \
        ac_cv_func_sched_setaffinity=no || exit 1
echo "Compiling and installing iPerf3"
make -j`nproc` && make install || exit 1
popd

# cURL
echo "Preparing cURL"
tar xvf ${CURL}.tar.bz2 || exit 1
pushd ${CURL}
mkdir build
cd build/
echo "Configuring and Compiling cURL"
cmake .. && make -j`nproc` || exit 1
popd

# NGINX
echo "Preparing NGINX"
gunzip ${NGINX}.tar.gz && tar xvf ${NGINX}.tar || exit 1
pushd ${NGINX}
echo "Configuring NGINX"
./configure --with-select_module --with-poll_module \
        --with-http_ssl_module --with-http_v2_module \
        --prefix=`pwd`/build || exit 1
echo "Compiling and installing NGINX"
make -j`nproc` && make install && \
        ln -s ../../../nginx/conf/nginx_{seng,pure_and_native}.conf build/conf/ || exit 1
popd

# WRK2
echo "Preparing wrk2"
unzip ${WRK2}.zip || exit 1
pushd wrk2-${WRK2}
echo "Compiling wrk2"
make -j`nproc` || exit 1
popd
