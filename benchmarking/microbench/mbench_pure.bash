#!/bin/bash
pushd ~/sgx-ra-tls/ >/dev/null 2>&1
SGX_MODE=HW make openssl/libnonsdk-ra-attester.a >/dev/null 2>&1 || exit 1
popd >/dev/null 2>&1

pushd ~/client_enclave/lwip_based_client_lib/build/ >/dev/null 2>&1
SGX_MODE=HW make -j4 >/dev/null 2>&1 || exit 1
popd >/dev/null 2>&1

GRAPHENE=~/sgx-ra-tls/deps/graphene/
BIN=build/pure_mbench
NAME=`basename "${BIN}"`
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

ulimit -n 512
sudo -E nice -n -20 ../../sgx-ra-tls/deps/graphene/Runtime/pal_loader "SGX" ${BIN}
