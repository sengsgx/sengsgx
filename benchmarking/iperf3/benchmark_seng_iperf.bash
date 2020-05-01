#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP as sole argument"
    exit 1
fi

DST_IP="$1"

BIN="../iperf-3.1.3/build/bin/iperf3"
FILESNAME="`basename ${BIN}`_seng"

ITERATIONS=5

IPERF_OPTS="--reverse --client $DST_IP --len 8K"
BANDWIDTH_LIST=( `seq 100 100 1000` )

IPERF="sudo -E nice -n -20 ../../sgx-ra-tls/deps/graphene/Runtime/pal_loader \"SGX\" ./${FILESNAME} $IPERF_OPTS"

function build_seng_libs () {
    # Update Attester library
    pushd ~/sgx-ra-tls/
    SGX_MODE=HW make openssl/libnonsdk-ra-attester.a || return 1
    popd

    # Update SENG libraries
    pushd ~/client_enclave/lwip_based_client_lib/build/
    SGX_MODE=HW make -j4 || return 1
    popd

    return 0
}

function sign_bench_binary () {
    # $1: should be path to the Binary
    # $2: basename of files to be generated

    ../../sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
        -libpal ../../sgx-ra-tls/deps/graphene/Runtime/libpal-Linux-SGX.so \
        -key ../../sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/signer/enclave-key.pem \
        -output "$2.manifest.sgx" -exec "$1" -manifest "$2.manifest" || return 1

    ../../sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token -output "$2.token" -sig "$2.sig" || return 1

    return 0
}

build_seng_libs || exit 1
sign_bench_binary "$BIN" "$FILESNAME"  || exit 1

ulimit -n 512 || exit 1

# Run iPerf3 once
for b in "${BANDWIDTH_LIST[@]}"
do
    echo "Bandwidth: $b"
    for i in `seq 1 ${ITERATIONS}`
    do
        SUCCESS=0
        echo "Iteration: $i"
        while [ "$SUCCESS" -eq "0" ]
        do
            echo "try"
            date
            # SUCCESS becomes 1 if grep failed, i.e. no failure message was printed
            eval "$IPERF --bandwidth ${b}M" 2>&1 | grep "Failed" >/dev/null
            SUCCESS=$?
            sleep 1
        done
    done
done
