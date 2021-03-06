FROM ubuntu:16.04

ARG root_passwd=seng
ARG cmake_src=cmake-3.14.0
ARG cmake_src_url=https://cmake.org/files/v3.14/${cmake_src}.tar.gz

RUN echo "root:${root_passwd}" | chpasswd

ARG username=encl-dev
#TODO: replace with `id --user` output
ARG userid=1000
ARG userhome=/home/${username}

ARG sgxsdk=sgx_linux_x64_sdk_2.2.100.45311.bin
ARG sgxsdk_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxsdk}

# create a normal user
# cf. `getent passwd $USER`
RUN useradd --create-home --shell /bin/bash --uid ${userid} ${username} && \
        mkdir --mode 755 ${userhome}/.ssh && \
        chown ${username}:${username} ${userhome}/.ssh

RUN apt-get update && apt-get install -y --no-install-recommends \
        coreutils \
        git \
        wget \
        build-essential \
        libssl-dev \
        libprotobuf-dev \
        autoconf \
        libtool \
        libprotobuf-c-dev \
        protobuf-c-compiler \
        protobuf-compiler \
        ca-certificates \
        automake \
        # GRAPHENE ##############################
        python \
        gawk \
        python-protobuf \
        python-crypto \
        socat \
        # for LSMOD required by PSW installer ###
        kmod \
        # convenience
        vim \
        # PYTHON PROTOTYPING ####################
        python3 \
        python3-pip \
        # NETWORKING ############################
        libuv1-dev \
        # for DOXYGEN in CMake ##################
        doxygen \
        graphviz

# SGX SDK (headers required)
RUN mkdir --mode 775 /opt/intel/ && \
        chgrp ${username} /opt/intel && \
        mkdir --mode 775 ${userhome}/downloads && \
        chown ${username}:${username} ${userhome}/downloads && \
        wget --directory-prefix ${userhome}/downloads ${sgxsdk_url} && \
        printf 'no\n/opt/intel\n' | su -c "bash ${userhome}/downloads/${sgxsdk}" ${username}

# for more convenient testing
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo htop less && \
        usermod -a -G sudo ${username} && \
        sed -i 's/%sudo\tALL=(ALL:ALL) ALL/%sudo\tALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers

# CMake 3.14 from source
RUN wget --directory-prefix /root/ ${cmake_src_url} && \
        cd /root/ && \
        gunzip ./${cmake_src}.tar.gz && \
        tar -xf ./${cmake_src}.tar && rm ./${cmake_src}.tar && \
        cd ./cmake-3.14.0 && \
        ./bootstrap && make -j`nproc` && make install && \
        make clean

# required for sgx driver when calling './build.sh graphene' in sgx-ra-tls repo
RUN apt-get update && apt-get install -y --no-install-recommends linux-headers-`uname -r`
