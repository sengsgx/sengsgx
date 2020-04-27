# SENG, the SGX-Enforcing Network Gateway

Documentation will be added in the near future.

* seng_runtime/ --  contains the client-side component based on Graphene-SGX

* seng_server/  --  contains the server-side component based on libuv

* seng_sdk/ --  contains the alternative client-side component without LibOS, but rather based on the Intel SGX SDK

Note: The following build steps were tested under Ubuntu 16.04.6 LTS and kernel 4.15.0-91. The client-side has already been successfully tested with an older container version on Ubuntu 18.04.2 LTS and kernel 4.15-0-47.

#Preparation
1. pull submodules:
	`git submodule update --init --recursive`

2. patch sgx-ra-tls:
	$cd sgx-ra-tls/
	$patch -p1 < ../patches/sgx-ra-tls_seng_changes.patch

*NOTE*: By default Graphene-SGX is built without(!) the experimental switchless/exitless O/ECALL pull request, as it can be instable and cause bugs/crashes in Graphene. There are 2 options to enable it:
(a) remove the # in line 120 of the patched sgx-ra-tls/build.sh file
(b) after compiling sgx-ra-tls [cf. step 8, inside base-container]:
	$cd ~/sgx-ra-tls/deps/graphene/
	$patch -p1 < ../../fixed_exitless_syscalls_pr405.patch
	$make SGX=1

3. add your own Intel Developer SPID to ra_tls_options.c:
	$vim sgx-ra-tls/ra_tls_options.c
4. add quote_type in ra_tls_options.c:
	$vim sgx-ra-tls/ra_tls_options.c
	Options:
	(a) SGX_LINKABLE_SIGNATURE
	(b) SGX_UNLINKABLE_SIGNATURE
5. add your own Intel Developer remote attestation subscription key to ias-ra.c:
	$vim sgx-ra-tls/ias-ra.c
	at line 228, replace the "YYY" with your subscription key

6. replace UID for container user, e.g., with `id --user` (cf. %TODO in dockerfile):
	$vim base_container/Dockerfile
7. build base container:
	$cd base_container/
	$docker-compose build
	Note: will try to install headers of your host kernel version
8. build sgx-ra-tls:
	$cd base_container/
	$docker-compose run --user encl-dev base-container
	$cd ~/sgx-ra-tls/
	$./build.sh graphene  *TODO* fix error/disable wolfssl build
	$./build.sh graphene
	$make

9. generate RSA key pair for server.
	e.g., for a demo:
	$cd seng_server/
	$openssl req -x509 -newkey rsa:3072 -keyout srv_key.pem -out srv_cert.pem -days 365 -nodes

#SENG Server
1. build server container:
	$cd seng_server/
	$docker-compose build
2. build SENG server:
	$cd seng_server/
	$docker-compose run --user encl-dev seng-server
	$cd ~/seng_server/double_tunnel_openssl/
	$mkdir build
	$cd build/
	$cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE
	$make

3. symlink server key pair:
	$cd build/
	$ln -s ../../srv_key.pem .
	$ln -s ../../srv_cert.pem .
4. configure SENG network interface:
 	Options:
 	(a) from host system (if running "host" networking mode in server container)
		$cd seng_server
		$./setup_seng_interface.bash
	(b) from inside server container [*TODO* requires installing iproute2 inside container]
		$sudo ~/seng_server/setup_seng_interface.bash
	
	note: if running "host" networking mode, (b) might run into nftables-iptables issues;

	*TODO* TUN device subnetwork must not collide with existing ones of the server;
	*TODO* alternatively might consider removing "host" networking mode and add port binding/forwarding to container
5. configure forwarding rules:
	*TODO* iptables rules to allow forwarding traffic between TUN interface and in/out host network interface(s)

6. Optional: Generate Sqlite3 demo database:
	$cd ~/seng_server/double_tunnel_openssl/
	$sqlite3 demo_sqlite3.db < seng_db_creator.sql

7. run SENG server:
	$cd build/
	$sudo ./src/seng_ossl_double_tunnel_server [-d <db>] <port>
8. gracefully shutdown SENG server:
	ctrl+C, wait

*NOTE*: The SENG Server currently uses 2 DTLS channels for the tunnel--one for each direction; Note that currently the 1st tunnel uses the CLI-chosen port number, while the 2nd one currently always uses 4711/udp. (cf. TODO)

#SENG Client-side

##Prerequisites
1. Install SGX driver at host
	we tested: https://github.com/intel/linux-sgx-driver/archive/2a509c203533f9950fa3459fe91864051bc021a2.zip
	$sudo apt-get install linux-headers-$(uname -r)
	$mkdir external/
	$cd external/
	$wget https://github.com/intel/linux-sgx-driver/archive/2a509c203533f9950fa3459fe91864051bc021a2.zip
	$unzip \*.zip

	build and install (cf. shipped instructions for installation); for demo, e.g.:
	$make
	$sudo insmod isgx.ko

	*note*: cf. driver readme for proper installation

2. Install PSW version 2.7.1 at host
	e.g. for Ubuntu 16.04 LTS:
	$cd external/

	$wget https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu16.04-server/libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb
	$sudo dpkg -i ./libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb

	check that aesmd is running:
	$service aesmd status
	"/var/run/aesmd/aesm.socket" should exist now

	(Optionally:
	$wget https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu16.04-server/libsgx-enclave-common-dev_2.7.101.3-xenial1_amd64.deb
	$sudo dpkg -i ./libsgx-enclave-common-dev_2.7.101.3-xenial1_amd64.deb)

	*NOTE* "SealedData" SDK sample did not work for us under that setup; (it worked under different SDK/PSW versions though, so we guess it is fixed under different versions/platforms) This does NOT affect SENG.

3. Install Graphene-SGX driver (legacy?) at host (optionally from build container), e.g.:
	$sudo insmod sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/sgx-driver/graphene-sgx.ko

##SENG Runtime
1. patch lwIP:
	$cd seng_runtime/lwip_based_client_lib/externals/lwip/
	$patch -p1 < ../../../../patches/total_lwip_patcher.patch

2. build runtime container:
	$cd seng_runtime/
	$docker-compose build

3. build SENG runtime:
	$cd seng_runtime/
	$docker-compose run --user encl-dev seng-runtime
	$cd ~/client_enclave/lwip_based_client_lib/
	$mkdir build
	$cd build/
	$cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE
	$make

*NOTE*: by default, SENG runtime is built w/o auto-nat/port shadowing support, i.e., server sockets are only reachable via the Enclave IP and NAT rules have to be manually added. To enable auto-nat, additionally define "SENG_AUTO_NAT":
	$cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE -DSENG_AUTO_NAT=true
	$make


##SENG SDK
1. fetch libraries:
	$cd seng_sdk/
	$./fetch_external_libs.bash
2. fetch NGINX and patch it:
	$./fetch_external_apps.bash

3. build SDK container:
	$docker-compose build

4. download, patch and build Intel SGX SDK+PSW:
	$docker-compose run --user encl-dev seng-sdk
	$cd ~/seng_sdk/
	$./build_patched_sdkpsw_sgxssl.bash

5. generate enclave signing key pair with exponent 3 for demo app and Nginx:
	$cd seng_sdk/enclave/app/src/
	$openssl genrsa -out app_enclave_private.pem -3 3072
	$openssl rsa -in app_enclave_private.pem -pubout -out app_enclave_public.pem

6. add public key of SENG server:
	$cd seng_sdk/
	$vim enclave/seng/src/DT_SSLEngineClient_OpenSSL.cpp

	at line 52, replace "ADD_YOURS" in the "ngw_hc_cert" variable with your public server key without newlines as should be output by:
	$sed '1d;$d;' ../seng_server/srv_cert.pem|tr -d \\n|tr \& \\\&

7. build SENG SDK libraries with demo app, followed by SENG-NGINX:
	$docker-compose run --user encl-dev seng-sdk
		[press "y" or "Y" on SDK/PSW re-install prompt]
	$cd ~/seng_sdk/
	$mkdir build
	$cd build/
	$cmake .. -DSGX_HW=ON -DCMAKE_BUILD_TYPE=RELEASE
	$make
	-----
	$cd ..
	$cd ported_external_apps/nginx-1.10.3/
	$../build_seng_nginx.bash


#Running Sample Applications

*NOTE*: ensure that you followed the setup steps above, s.t. all certificates and keys are in place, as well as the SENG interface and SGX driver/aesmd up and running.

*NOTE2*: you should only connect 1 enclave at once to the SENG server to avoid potential issues (cf. corresponding TODO entry)

##SENG Runtime
*NOTE*: In rare cases the shutdown process crashes with a 0x0 or SEGFAULT signal spam; we have not yet figured out why it happens sometimes; (might be fixed in newer Graphene versions where several race conditions/bugs got fixed)

###Demo App
What it does:
* connects to 192.168.178.45:8391/tcp
* send demo message through TCP connection

Prerequisites:
1. ensure that the SENG Server is running and using port 12345, localhost

Build the Demo App:
$cd seng_runtime/
$docker-compose run --user encl-dev seng-runtime
$cd ~/client_enclave/lwip_based_client_lib/demo_app/
$mkdir build
$cd build/
$cmake ..
$make

Run the Demo App:
$docker-compose run --user encl-dev seng-runtime
$cd ~/client_enclave/lwip_based_client_lib/demo_app/
$./run_demoapp.bash


###Real-world Apps
Prepare the apps:
$cd seng_runtime/
$docker-compose run --user encl-dev seng-runtime
$cd ~/benchmarking/
$./download_bench_progs.bash
$./build_bench_progs.bash

####iPerf3
The test script expects an iPerf3 server listening on 192.168.178.45 (at the host):
$sudo apt install iperf3
$iperf3 --server --bind 192.168.178.45

Run client:
$docker-compose run --user encl-dev seng-runtime
$cd ~/benchmarking/iperf3/

for SENG:
* ensure SENG server is running
* $./iperf_seng_test.bash

for Graphene-SGX w/o SENG (aka "pure"):
* $./iperf_pure_test.bash

####cURL
The test script fetches the root page of https://www.example.com.
$docker-compose run --user encl-dev seng-runtime
$cd ~/benchmarking/curl/

for SENG:
* ensure SENG server is running
* $./curl_seng_test.bash

for pure:
* $./curl_pure_test.bash

note: currently only IPv4 ('-4') is supported

####Telnet
The test script runs Telnet in IPv4 mode using the arguments passed to the script.
$docker-compose run --user encl-dev seng-runtime
$cd ~/benchmarking/telnet/


for SENG:
* ensure SENG server is running
* $./telnet_seng_test.bash <telnet_args>

for pure:
* $./telnet_pure_test.bash <telnet_args>

examples:
* Telnet login: ./telnet_seng_test.bash -l <user> <telnet_srv_ip> 23
* HTTP query:   ./telnet_seng_test.bash www.example.com 80
GET / HTTP/1.0\n
\n

Note: we only got 404 back from www.example.com when using netcat or telnet to issue a direct HTTP request to it, but it shows that sending the HTTP query and receiving the reply works.

*NOTEs*:
* IPv4 is enforced at the moment
* at the moment the target port has to be explicitly defined, because of lwIP's limited service-port resolution (will otherwise pick port 0; cf. todos)
* Graphene-SGX buffers messages before sending to stdout/stderr to reduce overhead; however, this is a problem, e.g., when running telnet without any arguments as it will not flush stdout and therefore not display the UI messages to the user; the output works fine for the HTTP example above


####NGINX
The test script runs NGINX inside Graphene-SGX and makes it expose an HTTP server on port 4711/tcp. HTTPS support is included in the config files, but commented out. It requires a server key pair. Note that Graphene-SGX w/o SENG ("pure") currently does not seem to support NGINX with HTTPS.

$docker-compose run --user encl-dev seng-runtime
$cd ~/benchmarking/nginx/

for pure:
* NGINX will be reachable under 192.168.178.45:4711/tcp
* $./nginx_pure_test.bash

for SENG (default)
* NGINX will be reachable via its assigned Enclave IP (cf. SENG server output) under port 4711.
* ensure SENG server is running
* $./nginx_seng_test.bash

for SENG (with enabled auto-NAT/port shadowing):
*TODO*

Connecting from host to..
..pure NGINX:
use port 4711/tcp and IP 192.168.178.45 (cf. respective NGINX configuration file)
$netcat 192.168.178.45 4711

..SENG NGINX (default):
use port 4711/tcp and the enclave IP assigned by the SENG server, probably 192.168.28.2
$netcat 192.168.28.2 4711

..SENG NGINX (auto-nat/shadowing):
*TODO*

In all cases you are now connected to NGINX and can issue an HTTP request:
[from netcat]
GET / HTTP/1.0\n
\n

to receive the NGINX demo page as result.

Alternatively the (stripped) bench script bench_with_wrk2.bash can be used which is based on wrk2, or wrk2 can be used directly, e.g.,
	./wrk --threads 2 --connections 100 --duration "10s" --rate <rate> --latency http://<ip>:4711/

*NOTE*: NGINX running under the SENG Runtime currently does not correctly handle ctrl+C for shutdown. It has to be killed instead. (cf. todo)

##SENG SDK
###Demo App
What it does:
1. Test O/ECALLs and switchless mode
* spawns enclave with 2 untrusted and 1 trusted worker thread (for switchless O/ECALLs)
* registers a signal handler for SIGALRM
* spawns a 2nd thread
* performs some demo regular and switchless O/ECALLS

2. SENG init and secure UDP communication
* initializes SENG via init_seng_runtime(<srvIP>, <srvPort>); -- 127.0.0.1:12345 for the demo
* creates 2 secure UDP and 1 secure TCP socket using the SENG API and closes them again (one of them double close)
* creates a secure UDP socket and "connects" with it to 192.168.178.45:8391
* sends multiple small messages to the destination through the SENG tunnel
* then waits for at most 2 reply messages by the destination; only for 1 if the first reply was >= 1501 Bytes
* then sends a 1404 Bytes message to the destination; the 1404 Bytes app data together with 20 Bytes IP header and 8 Bytes UDP header will result in a 1432 Bytes packet being sent through the SENG tunnel, which is the currently configured MTU for the virtual SENG interface;
* then waits for a reply with a receive timeout of 2 seconds to test the timeout feature added to the SGX PSW/SDK
* closes the secure UDP socket

3. Test the added timeout support in SGX PSW/SDK for condition variables
* waits on an SGX condition variable with 3 second timeout
* will indicate the successfully raised timeout

Prerequisites:
1. the Demo App is already compiled together with the SENG SDK
2. ensure that the SENG Server is running and using port 12345, localhost

Wait at host for DemoApp messages:
use a netcat instance to listen at 192.168.178.45:8391/udp;
the IP/port can be adapted in enclave/app/src/app_enclave.c: line 48 and 50;	

$netcat -u -n -l -p 8391 192.168.178.45 

Running the DemoApp:
$docker-compose run --user encl-dev seng-sdk
$cd ~/seng_sdk/build/
$./app/app/src/DemoApp


###SENG NGINX
What it does:
It runs NGINX inside an Intel SGX Enclave based on the Intel SGX SDK and the SENG SDK.

Prerequisites:
1. NGINX has been downloaded, patched and built as part of the SENG SDK installation steps above
2. ensure that the SENG Server is running and using port 12345, localhost

Running SENG NGINX:
$docker-compose run --user encl-dev seng-sdk
$cd ~/seng_sdk/ported_external_apps/nginx-1.10.3/build/
$./sbin/seng_nginx

Connecting from host to it:
use port 4711/tcp and the enclave IP assigned by the SENG server, probably 192.168.28.2

$netcat 192.168.28.2 4711

you are now connected to NGINX and can issue an HTTP request:
[from netcat]
GET / HTTP/1.0\n
\n

to receive the NGINX demo page as result.

wrk2 can be used to benchmark SENG NGINX (cf. benchmarking/ directory).


#TODOs
* localhost destination IPs through(!) tunnel are not yet working, because currently lwIP interprets them internally and refuses them;
* make IPs and Ports easier configurable at SENG Server, Runtime and SDK
* SENG currently does not make use of lwIP's IPv6 support yet

##sgx-ra-tls
* simplfy configuration of subscription key (note: newer version of sgx-ra-tls now also support the new IAS authentication method)
* option to only build the minimum of sgx-ra-tls required for the SENG server
* fix wolfssl compilation issue / disable unrequired builds in sgx-ra-tls

##server
* make the IP address configuration/bindings in SENG server easier configurable + more dynamic
* *CAUTION*: the SENG Server currently can have problems handling multiple Enclaves, because its current use of SO_REUSEPORT causes problems if newly connecting Enclaves are not bound to the current, fresh welcome socket by the kernel; cf. discussion in "SengServer_OpenSSL.cpp" for fixing it in a future version;
* change that the 2nd SENG server tunnel always uses 4711
* offer instructions for an alternative container variant without "host" networking mode
* provide option to run w/o shadowing server
* make IP(s) of shadowing server configurable

##runtime
* migrate to newer Graphene-SGX version
* remove SENG-dependencies from "pure" manifest files
* don't link shadow socket files if auto-nat/listen shadowing is disabled
* fix NGINX termination

##sdk
* FIX: currently SDK and PSW are installed inside the container, i.e., on restarts/reinstantiation, both are gone again; temporary work-arounded by adding the option to cause a direct re-install on container session start if it has been compiled before
* SENG SDK does not yet gracefully shutdown the enclave, but might hang on shutdown; this affects the DemoApp and SENG NGINX at the moment; the DemoApp can be terminated via ctrl+C, while NGINX currently has to be killed; -- we need to add a notification mechanism to wakeup the blocking recv/read() call of the tunnel thread and shutdown the lwIP thread before destroying the enclave;
* add support to SENG NGINX to change SENG Server IP+Port via NGINX config file
