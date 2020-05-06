#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Illegal number of parameters"
    echo "Pass the target IP as sole argument"
    exit 1
fi

DST_IP="$1"

pushd ~/sgx-ra-tls/
SGX_MODE=HW make openssl/libnonsdk-ra-attester.a || exit 1
popd

pushd ~/client_enclave/lwip_based_client_lib/build/
SGX_MODE=HW make -j4 || exit 1
popd

GRAPHENE=~/sgx-ra-tls/deps/graphene/
BIN=~/benchmarking/iperf-3.1.3/build/bin/iperf3
NAME=`basename "${BIN}"_seng`
MANI="${NAME}.manifest"

# generate graphene-sgx manifest with secure file hashes
${GRAPHENE}/Pal/src/host/Linux-SGX/signer/pal-sgx-sign \
    -libpal ${GRAPHENE}/Runtime/libpal-Linux-SGX.so \
    -key ${GRAPHENE}/Pal/src/host/Linux-SGX/signer/enclave-key.pem \
    -output ${MANI}.sgx -exec "${BIN}" \
    -manifest ${MANI} || exit 1

# generate SGX launch/init token
${GRAPHENE}/Pal/src/host/Linux-SGX/signer/pal-sgx-get-token \
    -output ${NAME}.token \
    -sig ${NAME}.sig || exit 1

# NOTE: alternatively run pal_loader with `sudo` instead of adapting mmap_min_addr for Graphene
#PREVAL=`sysctl vm.mmap_min_addr | awk "mmap_min_addr = \\$1 {print \\$3}"`

#echo "adapting vm.mmap_min_addr to 0"
#sudo sysctl -w vm.mmap_min_addr=0 >/dev/null

echo "*******************************************************************"

ulimit -n 512
#${GRAPHENE}/Runtime/pal_loader "SGX" ${NAME} "$@"
sudo nice -n -20 ${GRAPHENE}/Runtime/pal_loader "SGX" ${NAME} --reverse --client "${DST_IP}" --len 8K --bandwidth 1000M

echo "*******************************************************************"

#echo "restoring vm.mmap_min_addr setting"
#sudo sysctl -w vm.mmap_min_addr=${PREVAL} >/dev/null
