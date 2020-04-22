FROM seng/baseimage

ARG username=encl-dev
ARG userhome=/home/${username}

ARG sgxsdk=sgx_linux_x64_sdk_2.2.100.45311.bin
ARG sgxsdk_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxsdk}

ARG sgxpsw=sgx_linux_x64_psw_2.2.100.45311.bin
ARG sgxpsw_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxpsw}

# SGX SDK
RUN mkdir --mode 775 /opt/intel/ && \
        chgrp ${username} /opt/intel && \
        mkdir --mode 775 ${userhome}/downloads && \
        chown ${username}:${username} ${userhome}/downloads && \
        wget --directory-prefix ${userhome}/downloads ${sgxsdk_url} && \
        printf 'no\n/opt/intel\n' | su -c "bash ${userhome}/downloads/${sgxsdk}" ${username}

# SGX PSW
RUN wget --directory-prefix /root/ ${sgxpsw_url} && \
#RUN echo "43c43\n<             exit 4\n---\n>             #exit 4" | patch -p0 sgx_linux_x64_psw_2.2.100.45311.bin
        yes no /opt/intel | bash /root/${sgxpsw}

# for more convenient testing
RUN apt-get update && apt-get install -y --no-install-recommends \
        gdb net-tools \
        libpcre3-dev libexpat1-dev \
        netcat iperf3 iproute iptables \
        telnet tzdata

ENV user=${username}
CMD /home/${user}/client_enclave/bootup.bash

