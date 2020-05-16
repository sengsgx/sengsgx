# The SENG Runtime

## Overview
The SENG Runtime shields applications using Intel SGX and the Graphene-SGX library OS.
The Runtime uses lwIP as trusted network stack and OpenSSL to connect via DTLS tunnel to the SENG Server.
Network traffic of shielded apps only passes through the protected, attested DTLS tunnel. A patched version of sgx-ra-tls is used for binding the attestation report to the DTLS session.


## <a name="build" /> Building the SENG Runtime
0. follow the [build preparation steps](../README.md#buildprep) **and** [client-side build preparation steps](../README.md#clibuildprep)

1. patch lwIP:
    ```
    cd seng_runtime/lwip_based_client_lib/externals/lwip/
    patch -p1 < ../../../../patches/total_lwip_patcher.patch
    ```

2. build the SENG Runtime container:
    ```
    cd seng_runtime/
    docker-compose build
    ```

3. build the SENG runtime:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/client_enclave/lwip_based_client_lib/
    mkdir build
    cd build/
    cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE
    make
    ```

    Note: By default, the SENG runtime is built *without* the experimental support for automatic DNAT rules/port shadowing (cf. [SENG Server](../seng_server/README.md#shadowsrv)).
    As a consequence, you have to manually add NAT rules if you want the server sockets of Enclaves to be reachable beyond their Enclave IP, e.g., through the client host or gateway IP.
    If you want to try the *experimental support* for automatic DNAT rule creation instead, additionally define "SENG_AUTO_NAT" and consult the corresponding [NGINX section](#nginxshadow):
    ```
        # experimental
        cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE -DSENG_AUTO_NAT=true
        make
        
        # revert/undefine via -USENG_AUTO_NAT
    ```

4. [optional] compile the client-side helper tool for auto-nat/port shadowing:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/tools/cli_socket_blocker/
    mkdir build
    cd build/
    cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE
    make
    ```


## <a name="run" /> Running the SENG Runtime and its Demo App
**CAUTION**: in rare cases the shutdown process of the SENG Runtime causes a crash in Graphene with a 0x0 or SEGFAULT signal spam; we have not yet figured out why it sometimes happens; (might be fixed in newer Graphene versions where several race conditions/bugs got fixed)

### Integration into Graphene-SGX Manifest
The current prototype of the SENG Runtime integrates into Graphene-SGX as middle layer using the `LD_PRELOAD` primitive of the Graphene manifest file:
```
(...)
loader.env.LD_PRELOAD = /lib/libseng_ossl_double_onload.so
(...)
```
The onload library hooks the respective socket API functions and triggers the initialization of the SENG Runtime.
To allow loading and accessing all dependencies of the SENG Runtime, the respective dynamic libary files, the public key of the SENG Server and other files, e.g., trusted resolv.conf, have to be marked as trusted files in the manifest:
```
(...)
sgx.trusted_files.srvpubkey = file:<path>/middlebox_cert.pem

sgx.trusted_files.libonload = file:<path>/libseng_ossl_double_onload.so
sgx.trusted_files.libnetif = file:<path>/libseng_ossl_double_tunnel_netif.so
sgx.trusted_files.liblwip = file:<path>/liblwip.so

sgx.trusted_files.libprotobuf = file:<path>/libprotobuf.so.9
(... more ...)

sgx.trusted_files.resolv = file:<path>/resolv.conf
(... more ...)
(...)
```
Please refer to the manifest files and run scripts of the demo app and the real-world sample apps for full working examples.
Also cf. the documentation of [Graphene-SGX](https://github.com/oscarlab/graphene) for the full syntax of the manifest file.


### Building and Running the Demo App
What it does:
* connects to port `8391/tcp` of IPv4 given as 1st CLI argument
* sends demo message through TCP connection and exits

Prerequisites:
1. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
2. use netcat to listen for the connection:
    ```
    # [@host]
    netcat -4 -l <ip4_dst> 8391
    ```

**CAUTION**: For local tests, do **not** use the loopback address (127.0.0.1) as destination IP of the Demo App (cf. [limitations](../README.md#limitations)), but rather your internal host IP.

Build the Demo App:
```
cd seng_runtime/
docker-compose run --user encl-dev seng-runtime
cd ~/client_enclave/lwip_based_client_lib/demo_app/
mkdir build
cd build/
cmake ..
make
```

Run the Demo App:
```
# [@ seng-runtime]
cd ~/client_enclave/lwip_based_client_lib/demo_app/
./run_demoapp.bash <ip4_dst>
```
netcat should have received the "Hello world!" message.



## <a name="bench" /> Running and Benchmarking the real-world SENG Runtime sample Apps
The SENG Runtime ships with support for running 4 real-world applications: iPerf3, cURL, Telnet and NGINX.
All required files and scripts are located in the respective `benchmarking/` directories (`iperf3/`, `curl/`, `telnet/`, `nginx/`).
For each of the applications, we provide build instructions and scripts for running and benchmarking the app.
During benchmarking, we distinguish the following 3 modes of operation:
* *"native"* refers to native execution on Linux w/o Graphene and w/o SENG
* *"pure"* refers to execution inside Graphene-SGX, but w/o SENG
* *"seng"* refers to execution inside Graphene-SGX *with* SENG enabled

If you run the SENG Runtime, the SENG Server and the helper tools (e.g., wrk2) on separate machines, you have to ensure that you adapt the SENG Server address in the SENG Runtime accordingly.
Furthermore, you have to ensure that all traffic is routed through the SENG Server host (gateway), e.g., via combination of standard `ip route` routing rules and `iptables` DNAT rules.
For brevity, we only describe the setting for local testing.

Note: Depending on whether you test locally, internally or with external target hosts, you might want to tweak the TCP Window size of lwIP (cf. [lwipopts.h](lwip_based_client_lib/include/lwipopts.h)).
Sample configurations are provided.

### Preparation
We build iPerf3, cURL, NGINX and wrk2 from source, whereas we use the apt version of Telnet:
```
cd seng_runtime/
docker-compose run --user encl-dev seng-runtime
cd ~/benchmarking/
./download_bench_progs.bash
./build_bench_progs.bash
```

For all tests you have to ensure that the SENG Server is running.
By default, the SENG Runtime expects the SENG Server to listen on IP `127.0.0.1`, port `12345/udp`.



### iPerf3
#### Testing iPerf3
The test script runs iPerf3 for 10 seconds with a bandwidth (load) of max. 1 Gbps in reverse mode, i.e., the iPerf3 server to which it connects generates the traffic and the iPerf3 client (Enclave) receives it.

Prerequisites:
1. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
2. install iPerf3 on the host and run it in server mode (it will serve as traffic generator):
    ```
    # [@host]
    sudo apt install iperf3
    iperf3 --server --bind <host_ip4>
    ```
    
    **CAUTION**: For local tests, do **not** use the loopback address (127.0.0.1) as iPerf3 server IP (cf. [limitations](../README.md#limitations)), but rather your internal host IP.

3. enter the SENG Runtime container:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/iperf3/
    ```

Run iPerf3 with SENG:
```
# [@seng-runtime]
./test_seng_iperf.bash <host_ip4>
```

Run iPerf3 in "pure" mode (no SENG):
```
# [@seng-runtime]
./test_pure_iperf.bash <host_ip4>
```

Note: If you test locally and observe a high number of retransmissions, consider decreasing the TCP window size of lwIP.


#### Benchmarking iPerf3
The benchmark scripts for iPerf3 are located in `benchmarking/iperf3/` and basically run multiple iterations of the iPerf3 test with step-wise increasing bandwidth (default: 5 iterations, 100 Mbps steps till 1 Gbps).
The prerequisites are the same ones as for the iPerf3 test script.
For analysis, we suggest to run the iPerf3 server with the '--json' option:
```
iperf3 --server --bind <host_ip4> --json > `date "+%Y_%m_%d__%H_%M_%S"`_iperf.json
```

Bench iPerf3 in the different modes (run inside SENG Runtime container):
* native: `./benchmark_native_iperf.bash <host_ip4>`
* pure: `./benchmark_pure_iperf.bash <host_ip4>`
* SENG: `./benchmark_seng_iperf.bash <host_ip4>`






### cURL
#### Testing cURL
The cURL test script fetches the root page of `https://www.example.com` for demonstration.

Prerequisites:
1. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
2. enter the SENG Runtime container:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/curl/
    ```

Run cURL with SENG:
```
# [@seng-runtime]
./test_seng_curl.bash
```

Run cURL in "pure" mode (no SENG):
```
# [@seng-runtime]
./test_pure_curl.bash
```
Note: currently only IPv4 (`'-4'`) is supported


#### Benchmarking cURL
The benchmark scripts for cURL are located in `benchmarking/curl/` and fetch resources of increasing sizes (50 iterations each) from a given IPv4 address via `HTTP`, port `80/tcp`.
Please note that we have self-hosted a NGINX server for our evaluation which hosted files with 1KB data, 10KB, 100KB, 1MB, 10MB, etc. (cf. bench script).
The script currently only fetches the root page (`"/"`).
To enable the iterative fetching, please uncomment the alternative defintion of the `FILES` variable and host the respective files.
Measurement is done via the cURL built-in `time_total` option and the results are stored in the `results/` directory.

Bench cURL in the different modes (run inside SENG Runtime container):
* native: `./benchmark_native_curl.bash <host_ip4>`
* pure: `./benchmark_pure_curl.bash <host_ip4>`
* SENG: `./benchmark_seng_curl.bash <host_ip4>`

for testing, e.g., `./benchmark_native_curl.bash www.example.com`

**CAUTION**: For local tests, do **not** use the loopback address (127.0.0.1) as destination IP (cf. [limitations](../README.md#limitations)), but rather your internal host IP.




### Telnet

#### Testing Telnet
The test script runs Telnet in IPv4 mode using the arguments passed to the script.

Prerequisites:
1. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
2. enter the SENG Runtime container:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/telnet/
    ```

Run Telnet in the different modes (run inside SENG Runtime container):
* native: `./test_native_telnet.bash <telnet_args>`
* pure: `./test_pure_telnet.bash <telnet_args>`
* SENG: `./test_seng_telnet.bash <telnet_args>`

Examples:
* Telnet login: `./test_seng_telnet.bash -l <user> <telnet_srv_ip> 23`
* HTTP query:
    ```
    ./test_seng_telnet.bash www.example.com 80
    > GET / HTTP/1.0\n
    > \n
    ```
    (note: '\n' refers to pressing 'enter')

    Note: we only got 404 back from www.example.com when using netcat or telnet, but it demonstrates that sending the HTTP query and receiving the reply works.

Notes/Limitations:
* currently only IPv4 (`'-4'`) is supported
* the target port has to be explicitly defined, because of the currently limited service-port resolution (SENG)
* Graphene-SGX's current buffering of stdout/stderr can cause missing user output till the next flush, e.g., when running telnet w/o arguments; the output worked fine for us in the HTTP example; the delayed output does not(!) affect functionality, but only user experience in certain cases


#### Benchmarking Telnet
The run and helper scripts for benchmarking Telnet are located in `benchmarking/telnet/`.
The three benchmark scripts (`benchmark_<mode>_telnet.bash`) behave just like the test scripts, except that they additionally preload the `libapp_bench_onload.so` library.
The library measures the total runtime of Telnet and displays the result in microseconds.
For the evaluation, we have used a self-hosted Telnet server (cf. `telnet-server` on Fedora, `telnetd` on Ubuntu) running on a separate machine. 
The `create_data_files.bash` script generates the demo files used in the evaluation and `show_data_files.bash` shows the interaction with them.
As the standard Telnet client has no support for passing a set of commands, you have to either control it via a script or trigger commands remotely on login (e.g., via `bash_profile`).



### NGINX

#### Testing NGINX
The test script runs NGINX inside Graphene-SGX with a configured `HTTP` server on `port 4711/tcp` (cf. `nginx/conf/`). HTTPS support is included in the config files, but commented out as Graphene-SGX without SENG ("pure") currently does not seem to support NGINX with HTTPS due to missing `MSG_PEEK` support.

Prerequisites:
1. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
2. enter the SENG Runtime container:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/nginx/
    ```

Run NGINX in "native" mode (no LibOS, no SENG):
* NGINX will be reachable under `127.0.0.1:4711/tcp` as specified in `conf/nginx_pure_and_native.conf`
* run `./test_native_nginx.bash` 

Run NGINX in "pure" mode (no SENG):
* NGINX will be reachable under `127.0.0.1:4711/tcp` as specified in `conf/nginx_pure_and_native.conf`
* run `./test_pure_nginx.bash`

Run NGINX with SENG:
* NGINX will be reachable via its *assigned Enclave IP* (cf. SENG server output) under port `4711/tcp`
* ensure the SENG server is running
* run `./test_seng_nginx.bash`


Connecting from host to ..
* .. native/"pure" NGINX via: `netcat -4 127.0.0.1 4711`
* .. SENG-enabled NGINX via: `netcat -4 <enclave_ip> 4711`

In all cases you can query the NGINX demo page via a standard HTTP request:
```
# [from netcat]
> GET / HTTP/1.0\n
> \n
```
(note: '\n' refers to pressing 'enter')

Note: NGINX running under the SENG Runtime currently does not correctly handle ctrl+C for shutdown (cf. todo). Either press ctrl+C and then connect to it via netcat to trigger a graceful shutdown, or kill the container instead.



#### <a name="benchnginxruntime" /> Benchmarking NGINX
The script for benchmarking NGINX (`bench_with_wrk2.bash`) is located in `benchmarking/nginx/`.
The script uses `wrk2` to query the NGINX demo page (`"/"`) with step-wise increasing request rate and measure the per request latency.
The measurement results are parsed into a CSV format for simplified analysis and are stored in the `results/` directory.

Preparation: The script includes 3 different definitions of the `LOADS` variable which defines the request rates used by the benchmark.
Choose the one matching your NGINX mode or adapt to your needs.

For benchmarking, run NGINX as described above and then use the script to connect to NGINX by passing its IP address:
```
# [@seng-runtime / @external-host]
cd benchmarking/nginx/
./bench_with_wrk2.bash <nginx_ip>
```

Note: If running the SENG Runtime and SENG Server on separate hosts, you have to ensure that NGINX is reachable for the benchmarking host through the SENG Server host (gateway) by using standard routing rules and/or DNAT rules.




#### <a name="nginxshadow" /> Running NGINX with auto-nat/port shadowing enabled (Experimental!)
The SENG Runtime also supports running NGINX with SENG's experimental auto-nat/port shadowing feature enabled (cf. [build instructions](#build)).
The ShadowServer of the SENG Server (cf. [server section](../seng_server/README.md#shadowsrv)) will automatically add `DNAT` rules on the NGINX `listen()` call to make the NGINX enclave reachable under the client host IP (in addition to the Enclave IP).
The client host IP is the source IP of the DTLS tunnel as observed by the SENG Server.
All other aspects of running NGINX with the SENG Runtime remain the same as described above.

Preparation:
1. ensure you built the SENG runtime with `SENG_AUTO_NAT` defined
2. ensure you built the client socket blocker helper tool
3. ensure you created the `"SENG_output"` and `"SENG_prerouting"` chains as described in the [SENG Server documentation](../seng_server/README.md#shadowsrv)

Running:
1. ensure that the SENG Server is running with `'-s'` option and using IP `127.0.0.1`, port `12345/udp`
2. run the client helper tool used for blocking the ports in the host network stack (rejects if already blocked):
    ```
    docker-compose run --user encl-dev seng-runtime
    cd ~/tools/cli_socket_blocker/build/
    ./cli_sock_blocker
    ```
3. run NGINX (cf. notes above):
    ```
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/nginx
    ./test_seng_nginx.bash
    ```
4. use netcat to connect to NGINX via two options:
    * via the *assigned Enclave IP* (cf. server output) on port `4711/tcp`
    * via the *client host IP* on port `4711/tcp`, for which DNAT forwarding rules have been auto-added
    
    **CAUTION**: The *client host IP* is the host IP used for the DTLS tunnel.
    In the default setting, the IP will be `127.0.0.1` as the SENG Server also listens on `127.0.0.1` in that case.
    As lwIP currently does NOT(!) support the loopback address as destination address, you must *explicitly* specify a different source IP for netcat in that case (typically the host's internal network IP):
    
    ```
    netcat -4 -s <non_loopback_ip> 127.0.0.1 4711
    ```

Limitations:
* Support for automatic removal of the ShadowServer DNAT rules is not yet complete and therefore disabled. Remove the rules manually after each test run:
    ```
    sudo iptables -t nat -D SENG_output 1
    sudo iptables -t nat -D SENG_prerouting 1
    ```

* The client-side helper tool currently always binds to `127.0.0.1:2834/tcp` (cf. `CliSockBlocker.cpp`, lines 122 and 123). You have to replace the IP with the client host IP used for the DTLS tunnels if running a setup with separate machines (cf. todos).

* The client-side helper tool currently does not yet block the port explicitly for the host IP used for the DTLS tunnels (cf. todos).



## <a name="mbench" /> Running the Setup/Initialization Microbenchmarks
The setup microbenchmarks measure the initialization overhead of (i) Graphene-SGX and of (ii) the SENG Runtime.
The required manifest files and helper apps are located in `benchmarking/microbench/`.

Preparation:
1. build the helper apps:
    ```
    cd seng_runtime/
    docker-compose run --user encl-dev seng-runtime
    cd ~/benchmarking/microbench/
    mkdir build
    cd build/
    cmake ..
    make
    ```

Note: The results can be different depending on whether Graphene-SGX has been built without (default) or with support for exitless E/OCALLs.


### <a name="libosmbench" /> Graphene-SGX Microbenchmark
The Graphene-SGX microbenchmark measures the initialization time from Graphene's `main()` function till the `main()` function of the loaded application.

Preparation:
1. enable printing of the startup timestamp by uncommenting lines lines `831`, `844` and `845` in `sgx_main.c` (located in `sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/`)

2. recompile Graphene-SGX:
    ```
    # [@seng-runtime]
    cd ~/sgx-ra-tls/deps/graphene/
    make SGX=1
    ```

Run the Graphene-SGX Microbenchmark:
```
# [@seng-runtime]
cd ~/benchmarking/microbench/
./mbench_pure.bash
```

Interpreting the output:
* the 2 displayed numbers are the start (LibOS `main`) and end (app `main`) timestamps in microseconds
* the difference of the numbers is the approx. initialization time of Graphene-SGX
* adapt the memory and thread configurations in `microbench/pure_mbench.manifest` (3 sample configs are provided)




### <a name="sengmbench" /> SENG Runtime Microbenchmark
The SENG Runtime microbenchmark measures the different initialization phases of the SENG Runtime (excluding Graphene-SGX).

Preparation:
1. enable the `MEASURE_FINE_GRAINED_SETUP_TIME` macros in the following source files: 
    * `sgx-ra-tls/nonsdk-ra-attester.c:34`
    * `sgx-ra-tls/openssl-ra-attester.c:21`

2. recompile the sgx-ra-tls libraries:
    ```
    # [@seng-runtime]
    cd ~/sgx-ra-tls/
    make
    ```

3. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`

Run the SENG Runtime Microbenchmark:
```
# [@seng-runtime]
cd ~/benchmarking/microbench/
./mbench_seng.bash
```

Interpreting the output:
* the results are printed in a CSV format with the first row being the column names and the second the measurement results
* the results show the time of the respective initialization phase in microseconds
* the last value ("total_setup_usec") is the total intialization time of the SENG Runtime (excluding the LibOS init) in microseconds
