#!/bin/bash
pushd external

# dependencies for SDK and PSW
sudo apt-get update
sudo apt-get install zip fakeroot \
        build-essential ocaml automake autoconf libtool wget python libssl-dev \
        libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake \
        || exit 1

git clone --branch sgx_2.7.1 https://github.com/intel/linux-sgx.git || exit 1
pushd linux-sgx
patch -p1 < ../../patches/psw_sdk/WIP_timedwait_sdk_psw.patch || exit 1
./download_prebuilt.sh

# for psw pkg debug infos
export DEB_BUILD_OPTIONS="nostrip"

# SDK
make sdk USE_OPT_LIBS=0 DEBUG=1 || exit 1 # use sgxssl
make sdk_install_pkg USE_OPT_LIBS=0 DEBUG=1 || exit 1
./linux/installer/bin/sgx_linux_x64_sdk_2.7.101.3.bin || exit 1 # choose /opt/intel/

# PSW (requires SDK to be installed)
make psw DEBUG=1 || exit 1
make deb_pkg DEBUG=1 || exit 1
pushd ./linux/installer/deb
sudo dpkg -i libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb \
        libsgx-urts_2.7.101.3-xenial1_amd64.deb \
        || exit 1
sudo dpkg -i libsgx-enclave-common-dev_2.7.101.3-xenial1_amd64.deb \
        || exit 1

echo "WARNING: consider running `sudo service aesmd restart` at host now"

popd
popd
popd
exit 0
