#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP as sole argument"
    exit 1
fi

DST_IP="$1"

BIN="../iperf-3.1.3/build/bin/iperf3"
FILESNAME="`basename ${BIN}`_pure"

ITERATIONS=5

IPERF_OPTS="--reverse --client $DST_IP --len 8K"
BANDWIDTH_LIST=( `seq 100 100 1000` )

IPERF="sudo -E nice -n -20 ../../sgx-ra-tls/deps/graphene/Runtime/pal_loader \"SGX\" ./${FILESNAME} $IPERF_OPTS"

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

sign_bench_binary "$BIN" "$FILESNAME"  || exit 1
ulimit -n 512 || exit 1

# Run iPerf3
for b in "${BANDWIDTH_LIST[@]}"
do
    echo "Bandwidth: $b"
    for i in `seq 1 ${ITERATIONS}`
    do
        echo "Iteration: $i"
        date
        eval "$IPERF --bandwidth ${b}M" >/dev/null 2>/dev/null #|| exit 1
        sleep 1
    done
done
