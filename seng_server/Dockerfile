FROM seng/baseimage

ARG username=encl-dev
ARG userhome=/home/${username}

ARG sgxsdk=sgx_linux_x64_sdk_2.2.100.45311.bin
ARG sgxsdk_url=https://download.01.org/intel-sgx/linux-2.2/ubuntu64-desktop/${sgxsdk}

# SGX SDK (headers required)
RUN mkdir --mode 775 /opt/intel/ && \
        chgrp ${username} /opt/intel && \
        mkdir --mode 775 ${userhome}/downloads && \
        chown ${username}:${username} ${userhome}/downloads && \
        wget --directory-prefix ${userhome}/downloads ${sgxsdk_url} && \
        printf 'no\n/opt/intel\n' | su -c "bash ${userhome}/downloads/${sgxsdk}" ${username}

# for demo Sqlite3 support
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsqlite3-0 \
        libsqlite3-dev \
        sqlite3

# for auto-nat/shadowing
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables

# TODO: remove after ShadowServer migrated to OpenSSL
RUN apt-get update && apt-get install -y --no-install-recommends \ 
        libmbedtls10 \
        libmbedtls-dev

