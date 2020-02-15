FROM ubuntu:16.04

ARG root_passwd=lelandsaas
ARG cmake_src=cmake-3.14.0
ARG cmake_src_url=https://cmake.org/files/v3.14/${cmake_src}.tar.gz

RUN echo "root:${root_passwd}" | chpasswd

RUN apt-get update && apt-get install -y --no-install-recommends \
        coreutils \
        git \
        wget \
        openssh-client \
        build-essential \
        libssl-dev \
        libprotobuf-dev \
        autoconf \
        libtool \
        libprotobuf-c-dev \
        protobuf-c-compiler \
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
        # SSH SERVER ############################
        openssh-server \
        # convenience
        vim \
        # PYTHON PROTOTYPING ####################
        python3 \
        python3-pip \
        # NETWORKING ############################
        libasio-dev \
        libevent-dev \
        libuv1-dev \
        # DPDK ##################################
        dpdk-dev \
        # GO if required ########################
        golang-go \
        # for DOXYGEN in CMake ##################
        doxygen \
        graphviz && \
        # LIBSHADOWSOCKS based on libev
        # in Ubuntu repo only for >= 17
        apt-get install -y software-properties-common && \
        add-apt-repository -y ppa:max-c-lv/shadowsocks-libev && \
        apt-get update && \
        apt-get install -y libshadowsocks-libev-dev

# CMake 3.14 from source
RUN wget --directory-prefix /root/ ${cmake_src_url} && \
        cd /root/ && \
        gunzip ./${cmake_src}.tar.gz && \
        tar -xf ./${cmake_src}.tar && rm ./${cmake_src}.tar && \
        cd ./cmake-3.14.0 && \
        ./bootstrap && make -j`nproc` && make install && \
        make clean

# SSH Server
RUN mkdir /var/run/sshd && \
        sed -i 's/PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
        # SSH login fix. Otherwise user is kicked off after login
        sed 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@g' -i /etc/pam.d/sshd

# cf. https://stackoverflow.com/questions/36292317/why-set-visible-now-in-etc-profile
ENV NOTVISIBLE "in users profile"
RUN echo "export VISIBLE=now" >> /etc/profile

EXPOSE 22/TCP
CMD ["/usr/sbin/sshd", "-D"]
