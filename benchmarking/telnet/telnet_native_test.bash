#!/bin/bash
pushd ~/sgx-ra-tls/
SGX_MODE=HW make openssl/libnonsdk-ra-attester.a || exit 1
popd

pushd ~/client_enclave/lwip_based_client_lib/build/
SGX_MODE=HW make -j4 || exit 1
popd

PRELOAD="~/client_enclave/lwip_based_client_lib/build/dtls_tunnel_netif/src/libapp_bench_onload.so"
sudo -E nice -n -20 bash -c "LD_PRELOAD=${PRELOAD} telnet -4 ${*}" #| grep --text "app_time_in_usec"
