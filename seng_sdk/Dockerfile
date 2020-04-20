FROM seng/baseimage

ARG username=encl-dev
ARG userhome=/home/${username}

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

