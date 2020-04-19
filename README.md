# SENG, the SGX-Enforcing Network Gateway

Documentation will be added in the near future.

* seng_runtime/ --  contains the client-side component based on Graphene-SGX

* seng_server/  --  contains the server-side component based on libuv

* seng_sdk/ --  contains the alternative client-side component without LibOS, but rather based on the Intel SGX SDK


#Preparation
1. pull submodules:
	`git submodule update --init --recursive`
2. build base container:
	$cd base_container/
	$docker-compose build
3. generate RSA key pair for server.
	e.g., for a demo:
	$cd seng_server/
	$openssl req -x509 -newkey rsa:2048 -keyout srv_key.pem -out srv_cert.pem -days 365 -nodes
4. patch sgx-ra-tls:
	$cd sgx-ra-tls/
	$patch -p1 < ../patches/sgx-ra-tls_seng_changes.patch
5. add your own Intel Developer SPID to ra_tls_options.c:
	$vim sgx-ra-tls/ra_tls_options.c
6. add quote_type in ra_tls_options.c:
	$vim sgx-ra-tls/ra_tls_options.c
	Options:
	(a) SGX_LINKABLE_SIGNATURE
	(b) SGX_UNLINKABLE_SIGNATURE
7. add your own Intel Developer remote attestation subscription key to ias-ra.c:
	$vim sgx-ra-tls/ias-ra.c
	at line 228, replace the "YYY" with your subscription key
8. build sgx-ra-tls:
	$cd base_container/
	$docker-compose run base-container
	$su encl-dev
	$cd ~/sgx-ra-tls/
	$./build.sh graphene  %TODO: fix error/disable wolfssl build
	$./build.sh graphene

#SENG Server
0. replace UID for container user, e.g., with `id --user` (cf. %TODO in dockerfile)
1. build server container:
	$cd seng_server/
	$docker-compose build
2. 

#SENG Runtime

	$patch -p1 < ../../../../patches/total_lwip_patcher.patch


#SENG SDK



#TODOs
* simplfy configuration of subscription key (note: newer version of sgx-ra-tls now also support the new IAS authentication method)
* option to only build the minimum of sgx-ra-tls required for the SENG server