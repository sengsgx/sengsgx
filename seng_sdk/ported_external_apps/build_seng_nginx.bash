#!/bin/bash

set -x

make clean

source /opt/intel/sgxsdk/environment
SENG_PATH=~/client_enclave/sdk_based_version
EDL_PATHS="${SENG_PATH}/enclave/seng/include:${SENG_PATH}/external/sgxssl/Linux/package/include:${SENG_PATH}/external/seng_lwip_port/include:${SENG_PATH}/external/sgx-ra-tls/include:/opt/intel/sgxsdk/include:src/os/seng/trusted/"
sgx_edger8r --search-path "${EDL_PATHS}" \
    --untrusted-dir "src/os/seng/untrusted/" \
    --trusted-dir "src/os/seng/trusted/" \
    "src/os/seng/trusted/ngx_seng.edl" \
    || exit 1

# poll_module enabled
# http_module default enabled
# http_upstream_keepalive_module default enabled
# http_charset_module default enabled
# http_cache_module default enabled
### http_gzip_module default enabled

# --crossbuild="SENG:4.15.0-47-generic:x86_64" \
# TODO: remove static-libgcc??
./configure --help
./configure \
    --prefix="`pwd`/build" \
    \
    --with-cc-opt="-v -static -static-libgcc -fpic -fpie -fstack-protector -Wformat -Wformat-security -fvisibility=hidden -g" \
    --with-ld-opt="-static" \
    \
    --crossbuild="SENG:4.15.0-47-generic:x86_64" \
    \
    --without-select_module \
    --with-poll_module \
    --without-http_gzip_module \
    --without-http_ssi_module \
    --without-http_userid_module \
    --without-http_access_module \
    --without-http_auth_basic_module \
    --without-http_autoindex_module \
    --without-http_geo_module \
    --without-http_map_module \
    --without-http_split_clients_module \
    --without-http_referer_module \
    --without-http_rewrite_module \
    --without-http_proxy_module \
    --without-http_fastcgi_module \
    --without-http_uwsgi_module \
    --without-http_scgi_module \
    --without-http_memcached_module \
    --without-http_limit_conn_module \
    --without-http_limit_req_module \
    --without-http_empty_gif_module \
    --without-http_browser_module \
    --without-http_upstream_hash_module \
    --without-http_upstream_ip_hash_module \
    --without-http_upstream_least_conn_module \
    --without-http_upstream_zone_module \
    --without-mail_pop3_module \
    --without-mail_imap_module \
    --without-mail_smtp_module \
    --without-stream_limit_conn_module \
    --without-stream_access_module \
    --without-stream_upstream_hash_module \
    --without-stream_upstream_least_conn_module \
    --without-stream_upstream_zone_module \
    --without-pcre \
    || exit 1

make || exit 1
make install || exit 1
cp ../mini_nginx.conf ./build/conf/nginx.conf

# signing of enclave
sgx_sign sign -key ../app_enclave_private.pem -config ../ngx_seng_enclave.config.xml \
    -enclave ./build/sbin/nginx -out ./build/sbin/nginx_signed_enclave.so \
    || exit 1


# compile untrusted part
D="`pwd`"
U_FILES="$D/src/os/seng/untrusted/ngx_seng_u.c \
    $D/src/os/seng/untrusted/u_ngx_time.c \
    $D/src/os/seng/untrusted/u_ngx_files.c \
    $D/src/os/seng/untrusted/u_ngx_process_user.c \
    $D/src/os/seng/untrusted/u_ngx_rlimit.c \
    $D/src/os/seng/untrusted/u_ngx_process.c"

U_EXC="$D/src/os/seng/untrusted/nginx/u_nginx.c \
    $D/src/os/seng/untrusted/nginx/enclave_load.c"

U_INCS="-I$D/src/os/seng/untrusted -I$D/src/os/seng/untrusted/nginx"

OTH_INCS="-I/opt/intel/sgxsdk/include  -I$D/../../external/sgx-ra-tls/include"

pushd objs/src/os/seng/untrusted
gcc -c $U_INCS $OTH_INCS $U_FILES || exit 1
pushd nginx
gcc -c $U_INCS $OTH_INCS $U_EXC || exit 1
popd; popd

pushd ../../
B="`pwd`"
popd

LD_DIRS="$B/build/app/seng/src \
    $B/build/external"

LD_DIR_CMDS=""
for i in ${LD_DIRS[@]}
do
    LD_DIR_CMDS="$LD_DIR_CMDS -L$i"
done

# bake paths into executable
RPATHS=""
for i in ${LD_DIRS[@]}
do
    RPATHS="$RPATHS -Wl,-rpath,$i"
done

#Note: need the /usr/lib/ system libsgx_urts.co, otherwise will complain
LD_LIBS="-lseng_uruntime \
    -lratls_untrusted
    -lsgx_urts \
    "

# link untrusted part
gcc -o ./build/sbin/seng_nginx \
    ./objs/src/os/seng/untrusted/*.o \
    ./objs/src/os/seng/untrusted/nginx/*.o \
    $RPATHS \
    $LD_DIR_CMDS $LD_LIBS \
    || exit 1

echo "SUCCESS"

exit 0




# new, but not required anymore, bcs. nginx build already create the Enclave
ar rcs ./build/libnginx.a \
    objs/src/os/seng/trusted/core/t_nginx.o \
    objs/src/os/seng/trusted/core/t_ngx_cycle.o \
    objs/src/core/ngx_log.o \
    objs/src/core/ngx_palloc.o \
    objs/src/core/ngx_array.o \
    objs/src/core/ngx_list.o \
    objs/src/core/ngx_hash.o \
    objs/src/core/ngx_buf.o \
    objs/src/core/ngx_queue.o \
    objs/src/core/ngx_output_chain.o \
    objs/src/core/ngx_string.o \
    objs/src/core/ngx_parse.o \
    objs/src/core/ngx_parse_time.o \
    objs/src/core/ngx_inet.o \
    objs/src/core/ngx_file.o \
    objs/src/core/ngx_crc32.o \
    objs/src/core/ngx_murmurhash.o \
    objs/src/core/ngx_md5.o \
    objs/src/core/ngx_rbtree.o \
    objs/src/core/ngx_radix_tree.o \
    objs/src/core/ngx_slab.o \
    objs/src/core/ngx_times.o \
    objs/src/core/ngx_shmtx.o \
    objs/src/core/ngx_connection.o \
    objs/src/core/ngx_spinlock.o \
    objs/src/core/ngx_rwlock.o \
    objs/src/core/ngx_cpuinfo.o \
    objs/src/core/ngx_conf_file.o \
    objs/src/core/ngx_module.o \
    objs/src/core/ngx_resolver.o \
    objs/src/core/ngx_open_file_cache.o \
    objs/src/core/ngx_crypt.o \
    objs/src/core/ngx_proxy_protocol.o \
    objs/src/core/ngx_syslog.o \
    objs/src/event/ngx_event.o \
    objs/src/event/ngx_event_timer.o \
    objs/src/event/ngx_event_posted.o \
    objs/src/event/ngx_event_accept.o \
    objs/src/event/ngx_event_connect.o \
    objs/src/event/ngx_event_pipe.o \
    objs/src/os/unix/ngx_time.o \
    objs/src/os/seng/trusted/ngx_errno.o \
    objs/src/os/unix/ngx_alloc.o \
    objs/src/os/seng/trusted/ngx_files.o \
    objs/src/os/seng/trusted/ngx_socket.o \
    objs/src/os/unix/ngx_recv.o \
    objs/src/os/seng/trusted/ngx_readv_chain.o \
    objs/src/os/unix/ngx_udp_recv.o \
    objs/src/os/unix/ngx_send.o \
    objs/src/os/seng/trusted/ngx_writev_chain.o \
    objs/src/os/unix/ngx_udp_send.o \
    objs/src/os/seng/trusted/ngx_shmem.o \
    objs/src/os/seng/trusted/ngx_process.o \
    objs/src/os/seng/trusted/ngx_daemon.o \
    objs/src/os/seng/trusted/ngx_setaffinity.o \
    objs/src/os/unix/ngx_setproctitle.o \
    objs/src/os/unix/ngx_posix_init.o \
    objs/src/os/seng/trusted/ngx_user.o \
    objs/src/os/seng/trusted/ngx_process_cycle.o \
    objs/src/os/seng/trusted/ngx_seng_t.o \
    objs/src/os/seng/trusted/seng_misc_funcs.o \
    objs/src/os/seng/trusted/t_ngx_time.o \
    objs/src/os/seng/trusted/t_ngx_files.o \
    objs/src/os/seng/trusted/t_ngx_process_user.o \
    objs/src/os/seng/trusted/t_ngx_rlimit.o \
    objs/src/os/seng/trusted/ngx_seng_init.o \
    objs/src/event/modules/ngx_poll_module.o \
    objs/src/http/ngx_http.o \
    objs/src/http/ngx_http_core_module.o \
    objs/src/http/ngx_http_special_response.o \
    objs/src/http/ngx_http_request.o \
    objs/src/http/ngx_http_parse.o \
    objs/src/http/modules/ngx_http_log_module.o \
    objs/src/http/ngx_http_request_body.o \
    objs/src/http/ngx_http_variables.o \
    objs/src/http/ngx_http_script.o \
    objs/src/http/ngx_http_upstream.o \
    objs/src/http/ngx_http_upstream_round_robin.o \
    objs/src/http/ngx_http_file_cache.o \
    objs/src/http/ngx_http_write_filter_module.o \
    objs/src/http/ngx_http_header_filter_module.o \
    objs/src/http/modules/ngx_http_chunked_filter_module.o \
    objs/src/http/modules/ngx_http_range_filter_module.o \
    objs/src/http/modules/ngx_http_charset_filter_module.o \
    objs/src/http/modules/ngx_http_headers_filter_module.o \
    objs/src/http/ngx_http_copy_filter_module.o \
    objs/src/http/modules/ngx_http_not_modified_filter_module.o \
    objs/src/http/modules/ngx_http_static_module.o \
    objs/src/http/modules/ngx_http_index_module.o \
    objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
    objs/ngx_modules.o

exit 0


# old
ar rcs ./build/libnginx.a \
    objs/src/core/ngx_log.o \
    objs/src/core/ngx_palloc.o \
    objs/src/core/ngx_array.o \
    objs/src/core/ngx_list.o \
    objs/src/core/ngx_hash.o \
    objs/src/core/ngx_buf.o \
    objs/src/core/ngx_queue.o \
    objs/src/core/ngx_output_chain.o \
    objs/src/core/ngx_string.o \
    objs/src/core/ngx_parse.o \
    objs/src/core/ngx_parse_time.o \
    objs/src/core/ngx_inet.o \
    objs/src/core/ngx_file.o \
    objs/src/core/ngx_crc32.o \
    objs/src/core/ngx_murmurhash.o \
    objs/src/core/ngx_md5.o \
    objs/src/core/ngx_rbtree.o \
    objs/src/core/ngx_radix_tree.o \
    objs/src/core/ngx_slab.o \
    objs/src/core/ngx_times.o \
    objs/src/core/ngx_shmtx.o \
    objs/src/core/ngx_connection.o \
    objs/src/core/ngx_cycle.o \
    objs/src/core/ngx_spinlock.o \
    objs/src/core/ngx_rwlock.o \
    objs/src/core/ngx_cpuinfo.o \
    objs/src/core/ngx_conf_file.o \
    objs/src/core/ngx_module.o \
    objs/src/core/ngx_resolver.o \
    objs/src/core/ngx_open_file_cache.o \
    objs/src/core/ngx_crypt.o \
    objs/src/core/ngx_proxy_protocol.o \
    objs/src/core/ngx_syslog.o \
    objs/src/event/ngx_event.o \
    objs/src/event/ngx_event_timer.o \
    objs/src/event/ngx_event_posted.o \
    objs/src/event/ngx_event_accept.o \
    objs/src/event/ngx_event_connect.o \
    objs/src/event/ngx_event_pipe.o \
    objs/src/os/unix/ngx_time.o \
    objs/src/os/unix/ngx_errno.o \
    objs/src/os/unix/ngx_alloc.o \
    objs/src/os/unix/ngx_files.o \
    objs/src/os/unix/ngx_socket.o \
    objs/src/os/unix/ngx_recv.o \
    objs/src/os/unix/ngx_readv_chain.o \
    objs/src/os/unix/ngx_udp_recv.o \
    objs/src/os/unix/ngx_send.o \
    objs/src/os/unix/ngx_writev_chain.o \
    objs/src/os/unix/ngx_udp_send.o \
    objs/src/os/unix/ngx_channel.o \
    objs/src/os/unix/ngx_shmem.o \
    objs/src/os/unix/ngx_process.o \
    objs/src/os/unix/ngx_daemon.o \
    objs/src/os/unix/ngx_setaffinity.o \
    objs/src/os/unix/ngx_setproctitle.o \
    objs/src/os/unix/ngx_posix_init.o \
    objs/src/os/unix/ngx_user.o \
    objs/src/os/unix/ngx_dlopen.o \
    objs/src/os/unix/ngx_process_cycle.o \
    objs/src/os/unix/ngx_linux_init.o \
    objs/src/event/modules/ngx_epoll_module.o \
    objs/src/os/unix/ngx_linux_sendfile_chain.o \
    objs/src/event/modules/ngx_poll_module.o \
    objs/src/http/ngx_http.o \
    objs/src/http/ngx_http_core_module.o \
    objs/src/http/ngx_http_special_response.o \
    objs/src/http/ngx_http_request.o \
    objs/src/http/ngx_http_parse.o \
    objs/src/http/modules/ngx_http_log_module.o \
    objs/src/http/ngx_http_request_body.o \
    objs/src/http/ngx_http_variables.o \
    objs/src/http/ngx_http_script.o \
    objs/src/http/ngx_http_upstream.o \
    objs/src/http/ngx_http_upstream_round_robin.o \
    objs/src/http/ngx_http_file_cache.o \
    objs/src/http/ngx_http_write_filter_module.o \
    objs/src/http/ngx_http_header_filter_module.o \
    objs/src/http/modules/ngx_http_chunked_filter_module.o \
    objs/src/http/modules/ngx_http_range_filter_module.o \
    objs/src/http/modules/ngx_http_charset_filter_module.o \
    objs/src/http/modules/ngx_http_headers_filter_module.o \
    objs/src/http/ngx_http_copy_filter_module.o \
    objs/src/http/modules/ngx_http_not_modified_filter_module.o \
    objs/src/http/modules/ngx_http_static_module.o \
    objs/src/http/modules/ngx_http_index_module.o \
    objs/src/http/modules/ngx_http_upstream_keepalive_module.o \
    objs/ngx_modules.o

# note: if gzip, also requires -> objs/src/http/modules/ngx_http_gzip_filter_module.o \

# note: if http_gzip_module is enabled, also 'lz' required; else not
#cc -o ./build/nginx objs/src/core/nginx.o -static -L./build/ -lnginx -ldl -lpthread -lcrypto

