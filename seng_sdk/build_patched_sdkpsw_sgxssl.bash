#!/bin/bash
pushd external

# dependencies for SDK and PSW
#sudo apt-get update
#sudo apt-get install zip fakeroot \
#        build-essential ocaml automake autoconf libtool wget python libssl-dev \
#        libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper cmake \
#        || exit 1

#git clone --branch sgx_2.7.1 https://github.com/intel/linux-sgx.git || exit 1
wget https://github.com/intel/linux-sgx/archive/sgx_2.7.1.zip
unzip sgx_2.7.1.zip

#pushd linux-sgx
pushd linux-sgx-sgx_2.7.1
# main SENG-SDK patch for SDK/PSW
patch -p1 < ../../patches/psw_sdk/WIP_timedwait_sdk_psw.patch || exit 1
#TODO: this 2nd patch is only to fix compilation of the LocalAttestation and 
#      SampleEnclavePCL Intel SGX SDK Samples by adding includes to the EDL files;
#      the issue is fixed in release binaries and later versions of the Intel SGX SDK;
#  Note: the 2nd patch is not required for SENG-SDK;
patch -p1 < ../../patches/psw_sdk/sdk_workaround_fix.patch || exit 1
./download_prebuilt.sh

# for psw pkg debug infos
#export DEB_BUILD_OPTIONS="nostrip"

#note: add DEBUG=1 to make commands if required

# SDK
#note: USE_OPT_LIBS=0 uses SGXSSL rather than IPP crypto
make sdk USE_OPT_LIBS=0 || exit 1 # use sgxssl
make sdk_install_pkg USE_OPT_LIBS=0 || exit 1
printf 'no\n/opt/intel\n' | sudo ./linux/installer/bin/sgx_linux_x64_sdk_2.7.101.3.bin || exit 1 # choose /opt/intel/

# PSW (requires SDK to be installed)
make psw || exit 1
make deb_pkg || exit 1
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
