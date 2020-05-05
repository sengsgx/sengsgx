# The SENG SDK

## Overview
The SENG SDK consists of a trusted and untrusted enclave library for shielding the network traffic of Intel SGX SDK-based enclaves and connecting them to the SENG Server to enable app-grained firewall policies.
The SENG SDK uses lwIP as trusted network stack, [Intel SGX SSL](https://github.com/intel/intel-sgx-ssl) for setting up the DTLS tunnel connection and a patched version of sgx-ra-tls for binding the attestation report to the DTLS session.
Switchless E/OCALLs are used to speed up the tunnel operations.


## <a name="build" /> Building the SENG SDK
0. follow the [build preparation steps](../index.html#buildprep) **and** [client-side build preparation steps](../index.html#clibuildprep)

1. fetch libraries:
    ```
    cd seng_sdk/
    ./fetch_external_libs.bash
    ```
2. fetch NGINX and patch it:
    ```
    ./fetch_external_apps.bash
    ```

3. build the SENG SDK container:
    ```
    docker-compose build
    ```

4. download, patch and build Intel SGX SDK+PSW:
    ```
    cd seng_sdk/
    docker-compose run --user encl-dev seng-sdk
    cd ~/seng_sdk/
    ./build_patched_sdkpsw_sgxssl.bash
    ```

5. generate enclave signing key pair with exponent 3 for demo app and NGINX:
    ```
    cd seng_sdk/enclave/app/src/
    openssl genrsa -out app_enclave_private.pem -3 3072
    openssl rsa -in app_enclave_private.pem -pubout -out app_enclave_public.pem
    ```

6. add the SENG Server public key (certificate) to the SENG SDK by replacing `"ADD_YOURS"` in `seng_sdk/enclave/seng/src/DT_SSLEngineClient_OpenSSL.cpp:52` with the public key (*without* newlines)

7. build SENG SDK libraries with demo app, followed by the SENG SDK port of NGINX:
    ```
    cd seng_sdk/
    docker-compose run --user encl-dev seng-sdk
    # [press "y" or "Y" on SDK/PSW re-install prompt]

    cd ~/seng_sdk/
    mkdir build
    cd build/
    cmake .. -DSGX_HW=ON -DCMAKE_BUILD_TYPE=RELEASE
    make

    cd ..
    cd ported_external_apps/nginx-1.10.3/
    ../build_seng_nginx.bash
    ```

    **CAUTION**: Changes to the EDL files currently require `make clean` to wipe the old stub files.


## <a name="run" /> Running the SENG SDK and its Demo App

### Integration into Intel SGX SDK-based Enclaves
The SENG SDK integrates into Intel SGX SDK-based Enclaves like the standard APIs, i.e., the SENG SDK consists of a trusted and untrusted library pair.
To use the SENG SDK libraries, the following steps have to be done:
* the application must be linked against the untrusted `libseng_uruntime.so` library
* the enclave must be linked against the trusted `libseng_truntime.a` library
* the enclave's EDL file must import all functions from the `seng.edl` file
* the number of trusted enclave threads (`TCSMaxNum`) has to be increased by `+2` to cover the lwIP and tunnel thread
* for optimal performance, the enclave should enable switchless E/OCALLs and increase the number of untrusted worker threads (`num_uworkers`) by `+2` for fast tunnel recv/send operations
* the enclave must include the `seng_api.hpp` header and init SENG via `init_seng_runtime(..)` before calling the SENG socket API functions

See the files of the SENG SDK Demo App and NGINX port for working examples. 


### Running the Demo App
What it does:
* spawns enclave with 2 untrusted worker threads (for switchless OCALLs)
* calls into Enclave
* performs a demo switchless OCALL
* initializes SENG with `127.0.0.1:12345` as the address of the SENG Server
* creates 2 secure UDP and 1 secure TCP socket using the SENG API and closes them again
* creates a secure TCP socket and connects with it to port `8391/tcp` of the IPv4 address given as 1st CLI argument
* sends 5 times a demo message and then waits 4 seconds for a reply message before closing the socket
* tests the added timeout support for condition variables by waiting 2 seconds with timeout (will be successfully raised)

Prerequisites:
1. the Demo App is already compiled together with the SENG SDK
2. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`
3. use netcat to listen for the connection:
    ```
    # [@host]
    netcat -4 -l <ip4_dst> 8391
    ```

**CAUTION**: For local tests, do **not** use the loopback address (127.0.0.1) as destination IP of the Demo App (cf. [limitations](../index.html#limitations)), but rather your internal host IP.

Run the DemoApp:
```
docker-compose run --user encl-dev seng-sdk
cd ~/seng_sdk/build/
./app/app/src/DemoApp <ip4_dst>
```

Note: The SENG SDK does not yet implement a graceful shutdown procedure, therefore you have to terminate the enclave with Ctrl+C and might have to restart the SENG Server to cleanup the tunnel (cf. [limitations](../index.html#limitations)).



## <a name="bench" /> Running and Benchmarking the SENG SDK port of NGINX
We have ported NGINX to the SENG SDK, s.t. it runs inside an SGX enclave and the SENG Server can enable app-grained firewall policies for it.
The default policy defines an `HTTP` server on port `4711/tcp` which hosts the NGINX demo web page.

Prerequisites:
1. NGINX has been downloaded, patched and built as part of the SENG SDK installation steps above
2. ensure that the SENG Server is running and using IP `127.0.0.1`, port `12345/udp`

Run SENG NGINX:
```
cd seng_sdk/
docker-compose run --user encl-dev seng-sdk
cd ~/seng_sdk/ported_external_apps/nginx-1.10.3/build/
./sbin/seng_nginx
```

Use netcat to connect from the host to NGINX using the Enclave IP assigned by the SENG Server (cf. server output, e.g., 192.168.28.2) and port `4711/tcp`:
```
netcat -4 <enclave_ip> 4711
```
Afterwards you can query the NGINX demo page via a standard HTTP request:
```
# [from netcat]
> GET / HTTP/1.0\n
> \n
```
(note: '\n' refers to pressing 'enter')

### Benchmarking
The benchmarking script is the same one used for the SENG Runtime and is located in `benchmarking/nginx/bench_with_wrk2.bash` (cf. [SENG Runtime section](../seng_runtime/index.html#benchnginxruntime)).
The script uses [wrk2](https://github.com/giltene/wrk2) to measure the request latency under step-wise increasing request rates.
For benchmarking the SENG SDK port of NGINX, we recommend running NGINX, the SENG Server and the benchmarking script on 3 seperate machines.


Perform the following steps:
* ensure that the SENG Server is running
* run the SENG SDK port of NGINX as described above and check that it has successfully connected to the SENG Server
* check that the `LOADS` variable in `bench_with_wrk2.bash` is set to the desired request rates
* run the benchmarking script with the IPv4 address under which SENG NGINX is reachable:
    ```
    # [@seng-runtime / @external-host]
    cd benchmarking/nginx/
    ./bench_with_wrk2.bash <nginx_ip>
    ```

Notes:
* you must adapt the SENG Server address in the `init_seng_runtime(..)` call of the NGINX SENG SDK port if you run them on different machines
* if the Enclave subnetwork uses a private IP range and the benchmarking script does not run on the same host as the SENG Server, you have to make the NGINX enclave reachable through the gateway via a DNAT rule 
