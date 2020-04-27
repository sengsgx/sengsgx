#!/bin/bash
GRAPHENE=~/sgx-ra-tls/deps/graphene/
BIN=~/benchmarking/nginx-1.10.3/build/sbin/nginx
NAME=`basename "${BIN}"_pure`
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
sudo nice -n -20 ${GRAPHENE}/Runtime/pal_loader "SGX" ${NAME} -c conf/nginx_pure_and_native.conf

echo "*******************************************************************"

#echo "restoring vm.mmap_min_addr setting"
#sudo sysctl -w vm.mmap_min_addr=${PREVAL} >/dev/null
