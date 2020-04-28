FROM seng/baseimage

ARG username=encl-dev
ARG userhome=/home/${username}

# Uninstall old Intel SGX SDK
RUN /opt/intel/sgxsdk/uninstall.sh && rmdir /opt/intel/ && \
    rm /home/${username}/downloads/sgx_linux_x64_sdk_2.2.100.45311.bin && \
    rmdir /home/${username}/downloads/

# Dependencies for compilation of Intel SGX and PSW
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ocaml automake autoconf libtool wget python libssl-dev \
    libssl-dev libcurl4-openssl-dev protobuf-compiler libprotobuf-dev debhelper

# More required tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    zip fakeroot unzip curl lsb-release

# SENG SDK dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libprotoc-dev

ENV user=${username}
CMD /home/${user}/seng_sdk/sdk_docker_bootstrap.bash

