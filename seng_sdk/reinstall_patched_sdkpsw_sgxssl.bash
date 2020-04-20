#!/bin/bash
pushd external
pushd linux-sgx-sgx_2.7.1

# SDK
printf 'no\n/opt/intel\n' | sudo ./linux/installer/bin/sgx_linux_x64_sdk_2.7.101.3.bin || exit 1 # choose /opt/intel/

# PSW (requires SDK to be installed)
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
