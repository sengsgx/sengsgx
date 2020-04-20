#!/bin/bash
set +x

P_DIR="../patches/"
EXT_DIR="external/"
pushd ${EXT_DIR} || (echo "Call from main directory" && exit 1)

# Fetch lwIP 2.1.0
#LWIP_URL="http://download.savannah.nongnu.org/releases/lwip/lwip-2.1.0.zip"
#LWIP_CONTRIB_URL="http://download.savannah.nongnu.org/releases/lwip/contrib-2.1.0.zip"

#LWIP="lwip-2.1.0"
#LWIP_CONTRIB="contrib-2.1.0"

#wget ${LWIP_URL} ${LWIP_CONTRIB_URL} && \
#unzip "${LWIP}.zip" && unzip "${LWIP_CONTRIB}.zip" && \
#mv ${LWIP} "lwip" && mv ${LWIP_CONTRIB} "lwip/contrib" || exit 1

# moved include for preventing redefinition errors
#cp ${P_DIR}/lwip/arch.h lwip/src/include/lwip/arch.h || exit 1

# Clone lwIP 2.1.2 and contrib 2.1.0
git clone --branch STABLE-2_1_2_RELEASE https://git.savannah.nongnu.org/git/lwip.git/ lwip
git clone --branch STABLE-2_1_0_RELEASE https://git.savannah.gnu.org/git/lwip/lwip-contrib.git lwip/contrib

# apply minor fixes and POSIX-LINUX compliance patch
pushd lwip && \
    patch -p1 < ../${P_DIR}/lwip/extfixes_and_our_posixpatch.patch && \
    patch -p1 < ../${P_DIR}/lwip/prevent_endian_redefs.patch && \
    popd || exit 1


# Fetch SGX SSL for SDK 2.2
SGXSSL_URL="https://github.com/intel/intel-sgx-ssl/archive/v2.2.tar.gz"
OSSL_URL="https://github.com/openssl/openssl/archive/OpenSSL_1_1_0e.tar.gz"

SGXSSL="intel-sgx-ssl-2.2"
OSSL_VER="openssl-OpenSSL_1_1_0e"

wget ${SGXSSL_URL} -O "${SGXSSL}.tar.gz" && \
gunzip "${SGXSSL}.tar.gz" && tar xvf "${SGXSSL}.tar" && mv ${SGXSSL} "sgxssl" && \
pushd "sgxssl/openssl_source" && \
wget ${OSSL_URL} -O "${OSSL_VER}.tar.gz" && \
gunzip "${OSSL_VER}.tar.gz" && tar xvf "${OSSL_VER}.tar" && mv ${OSSL_VER} "OpenSSL_1.1.0e" && \
tar cfv "OpenSSL_1.1.0e.tar" "OpenSSL_1.1.0e" && gzip "OpenSSL_1.1.0e.tar" && rm -r "${OSSL_VER}.tar" "OpenSSL_1.1.0e" && \
popd || exit 1

# patches
cp ${P_DIR}/sgxssl/build_openssl.sh sgxssl/Linux/ && \
cp ${P_DIR}/sgxssl/bypass_to_sgxssl.h sgxssl/openssl_source/ && \
cp ${P_DIR}/sgxssl/sgx_tsgxssl.edl sgxssl/Linux/package/include/ && \
cp ${P_DIR}/sgxssl/libsgx_tsgxssl/* sgxssl/Linux/sgx/libsgx_tsgxssl/ && \
cp ${P_DIR}/sgxssl/sgx/Makefile sgxssl/Linux/sgx/ && \
cp ${P_DIR}/sgxssl/bss_dgram.c sgxssl/openssl_source/ && \
cp ${P_DIR}/sgxssl/dtls1.h sgxssl/openssl_source/ || exit 1


# Fetch Protobuf-C 1.2.1
PROTO_C_URL="https://github.com/protobuf-c/protobuf-c/releases/download/v1.2.1/protobuf-c-1.2.1.tar.gz"
PROTO_C="protobuf-c-1.2.1"

wget ${PROTO_C_URL} && \
gunzip "${PROTO_C}.tar.gz" && tar xvf "${PROTO_C}.tar" || exit 1

# patches
cp ${P_DIR}/protobuf/CMakeLists.txt protobuf-c-1.2.1/build-cmake/ && \
cp -r ${P_DIR}/protobuf/tlib protobuf-c-1.2.1/build-cmake/ || exit 1


# Done
popd
exit 0
