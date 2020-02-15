#!/bin/bash
set +x

APP_DIR="ported_external_apps/"
pushd ${APP_DIR} || (echo "Call from main directory" && exit 1)

# Fetch nginx 1.10.3
NGINX_URL="https://nginx.org/download/nginx-1.10.3.tar.gz"
NGINX="nginx-1.10.3"

wget ${NGINX_URL} && \
gunzip "${NGINX}.tar.gz" && tar xvf "${NGINX}.tar" \
|| exit 1

# patches
pushd ${NGINX}
patch -p1 < "../WIP_nginx_seng.patch"
popd

# Done
popd
exit 0
