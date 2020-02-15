FROM syssec/devimage

ARG username=encl-dev
ARG userid=10145
ARG userhome=/home/${username}

ARG sgxsdk=sgx_linux_x64_sdk_2.2.100.45311.bin
ARG sgxsdk_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxsdk}

ARG sgxpsw=sgx_linux_x64_psw_2.2.100.45311.bin
ARG sgxpsw_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxpsw}

# create a normal user
# cf. `getent passwd $USER`
RUN useradd --create-home --shell /bin/bash --uid ${userid} ${username} && \
        mkdir --mode 755 ${userhome}/.ssh && \
        chown ${username}:${username} ${userhome}/.ssh

# SGX SDK and PSW binaries
RUN mkdir --mode 775 /opt/intel/ && \
        chgrp ${username} /opt/intel && \
        mkdir --mode 775 ${userhome}/downloads && \
        chown ${username}:${username} ${userhome}/downloads && \
        wget --directory-prefix ${userhome}/downloads ${sgxsdk_url} && \
        printf 'no\n/opt/intel\n' | su -c "bash ${userhome}/downloads/${sgxsdk}" ${username}

RUN wget --directory-prefix /root/ ${sgxpsw_url} && \
#RUN echo "43c43\n<             exit 4\n---\n>             #exit 4" | patch -p0 sgx_linux_x64_psw_2.2.100.45311.bin
        yes no /opt/intel | bash /root/${sgxpsw}

# for the protobuf file
RUN apt-get update && apt-get install -y --no-install-recommends \
        protobuf-compiler

# for more convenient testing
RUN apt-get update && apt-get install -y --no-install-recommends \
        sudo gdb zsh net-tools strace \
        libpcre3-dev libexpat1-dev \
        netcat iperf3 iproute iptables \
        htop less telnet && \
        usermod -a -G sudo encl-dev && \
        sed -i 's/%sudo\tALL=(ALL:ALL) ALL/%sudo\tALL=(ALL:ALL) NOPASSWD:ALL/' /etc/sudoers

# required for sgx driver when calling './build.sh graphene' in sgx-ra-tls repo
RUN apt-get update && apt-get install -y --no-install-recommends linux-headers-`uname -r`

#RUN mkdir /dev/net && mknod /dev/net/tun c 10 200 && \
#    chmod 600 /dev/net/tun
