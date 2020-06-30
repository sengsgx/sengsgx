FROM seng/baseimage

ARG username=encl-dev
ARG userhome=/home/${username}

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

# for the SENG Netfilter module, iptables extension and user-space library
RUN apt-get update && apt-get install -y --no-install-recommends \
        libnl-genl-3-dev \
        libnetfilter-conntrack-dev
