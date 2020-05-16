# SENG Server

## Overview
The SENG Server attests shielded apps and tunnels authenticated IPv4 enclave traffic
between the SENG client components and the gateway firewall via a TUN interface. The 
SENG Server waits for DTLS tunnel connections by the SENG Runtime or SENG SDK.
The current implementation of the SENG Server is based on [libuv](https://libuv.org/),
[OpenSSL](https://www.openssl.org/) and a patched version of
[sgx-ra-tls](https://github.com/cloud-security-research/sgx-ra-tls).


## <a name="build" /> Building the SENG Server
0. follow the [build preparation steps](../README.md#buildprep)

1. build the SENG Server container:
    ```
    cd seng_server/
    docker-compose build
    ```

2. build the SENG server:
    ```
    docker-compose run --user encl-dev seng-server
    cd ~/seng_server/double_tunnel_openssl/
    mkdir build
    cd build/
    cmake .. -DSGX_MODE=HW -DCMAKE_BUILD_TYPE=RELEASE
    make
    ```

3. symlink server key pair:
    ```
    # [build/]
    ln -s ../../srv_key.pem .
    ln -s ../../srv_cert.pem .
    ```

### Configure the tunnel interface and firewall
4. configure SENG network interface (`"tunFA"`) from host, or from server container:
    ```
    # [@host]
    cd seng_server
    ./setup_seng_interface.bash
    ```
    or:
    ```
    # [@seng-server]
    cd ~/seng_server
    ./setup_seng_interface.bash
    ```

    By default the MTU is set to `1432` and the interface gets the following two local IP addresses: `192.168.28.1/24` and `172.16.28.1/24`, following the sample Enclave IP subnetworks.
    Please adapt to your needs.

    The setup can be removed via `./teardown_seng_interface.bash`

5. configure firewall rules:
    1. If the FORWARD default rule is DROP, allow packet forwarding from/to Enclave Subnetworks:
        ```
        # [@host or @seng-server]
        sudo iptables -A FORWARD -i tunFA -o eno1 --src 192.168.28.0/24 -j ACCEPT
        sudo iptables -A FORWARD -i tunFA -o eno1 --src 172.16.28.0/24 -j ACCEPT
        sudo iptables -A FORWARD -i eno1 -o tunFA --dst 192.168.28.0/24 -j ACCEPT
        sudo iptables -A FORWARD -i eno1 -o tunFA --dst 172.16.28.0/24 -j ACCEPT
        ```

    2. For DNS APIs like getaddrinfo(), the SENG Runtime and SDK currently use 8.8.8.8 as DNS Server through the secure tunnel. For this to work, NAT has to be enabled for Enclave packets to external clients:
        ```
        # [@host or @seng-server]
        sudo iptables -t nat -A POSTROUTING --src 192.168.28.0/24 -o eno1 -j MASQUERADE
        sudo iptables -t nat -A POSTROUTING --src 172.16.28.0/24 -o eno1 -j MASQUERADE
        ```

    Note: For both cases, adapt `"eno1"` to the name of your network interface(s). Also cf. comments in `setup_seng_interface.bash` and `teardown_seng_interface.bash` for the commands.


## <a name="run" /> Running the SENG Server
The SENG Server has to be run from inside the SENG Server container. While it requires
`sudo` for adapting iptables rules if auto-nat/shadowing is used, it temporary drops the
elevated privileges and only makes use of them on demand for issuing iptables commands.
Separation of the ShadowServer or its iptables component into a separate process is a *todo*.
The SENG Server currently uses 2 DTLS tunnels: one for receiving data from the shielded
apps and one for sending data. The 2nd tunnel uses `(<tunnel_port> + 1)` as UDP port.

```
Usage: seng_ossl_tunnel_server [-d <sqlite.db>] [-s] <tunnel_ipv4> <tunnel_port>

Arguments:
tunnel_ipv4     = IPv4 address on which the server will listen
tunnel_port     = UDP port on which the server will listen

Options:
-d <sqlite.db>  = optional path to SQLite3 database
-h              = show this help message
-s              = enable ShadowServer for auto-nat/port shadowing at 192.168.28.1:2409/tcp
```
**CAUTION**: The '-s' option is experimental and currently incompatible with the '-d' option, because the ShadowServer only binds to `192.168.28.1:2409/tcp` (hardcoded).


### <a name="serverdefault" /> Running the SENG Server in default mode
Note: At the moment, the SENG Server always uses `192.168.28.0/24` as the only Enclave
IP Subnetwork if running without '-d' option.
```
cd seng_server/
docker-compose run --user encl-dev seng-server
cd ~/seng_server/double_tunnel_openssl/build/
sudo ./src/seng_ossl_double_tunnel_server 127.0.0.1 12345
```
Use `Ctrl+C` to gracefully shut down the SENG Server. It can take a few seconds before
the shutdown request is handled.

**CAUTION**: At the moment `127.0.0.1:12345/udp` is hardcoded in the SENG Runtime,
SENG SDK Demo App and SENG SDK NGINX port as the SENG Server address. If you 
want to use a different SENG Server address, you have to manually adapt them at the
moment:
* SENG Runtime: [DT_RaSSLTunnelNetif_OpenSSL.cpp:58/59](../seng_runtime/lwip_based_client_lib/dtls_tunnel_netif/src/DT_RaSSLTunnelNetif_OpenSSL.cpp#L58)
* SENG SDK Demo App: [app_enclave.cpp:28](../seng_sdk/enclave/app/src/app_enclave.cpp#L30)
* SENG SDK NGINX port: [nginx-1.10.3/src/os/seng/trusted/ngx_seng_init.c:42](../seng_sdk/ported_external_apps/WIP_nginx_seng.patch#L7208)


### Running the SENG Server with the demo SQLite3 database
When passing a SQLite3 database to the SENG Server, the SENG Server will use the Enclave
Subnetworks defined in the database.
Furthermore, the SENG Server will use the specified enclave/app whitelist to (i) authenticate the attested apps, (ii) select the Enclave Subnetwork from which to assign an IP to the connected enclave/app.
```
# [@seng-server]
cd ~/seng_server/double_tunnel_openssl/
sqlite3 demo_sqlite3.db < seng_db_creator.sql
cd build/
sudo ./src/seng_ossl_double_tunnel_server -d ../demo_sqlite3.db 127.0.0.1 12345
```
The current SQLite3 demo database defines 2 enclave subnetworks: (i) `192.168.28.0/24` and (ii) `172.16.28.0/26`.
Subnetwork (i) only whitelists the SENG SDK Demo App for client hosts from the internal subnetwork `127.0.0.1/26`.
Subnetwork (ii) only whitelists the SENG SDK port of NGINX for clients from `127.0.0.1/26`.
In a real setup, you should adapt the host IP subnet(s), e.g., to `10.0.0.0/26`.
Admins can define app-specific firewall rules by defining them on the IPs of (i), (ii) or both, for example:
```
# [@host]
# allow Demo App enclaves to connect to NGINX enclaves (just for demonstration) 
sudo iptables -A FORWARD \
    --src 192.168.28.0/24 -i tunFA \
    -o tunFA --dst 172.16.28.0/26 -p tcp --destination-port 4711 \
    -j ACCEPT
    
# (reverse direction skipped)
```
Please cf. [the SQL file](double_tunnel_openssl/seng_db_creator.sql) for the demo database scheme.
The `"enclave_subnets"` table defines the Enclave Subnetworks and the `"apps"` table specifies the whitelisted apps together with the client subnetwork for which they are allowed, as well as the Enclave Subnetwork from which to assign the Enclave IPs.
If you change the Enclave Subnetworks, you also have to adapt the IP addresses of the `"tunFA"` interface and your firewall rules.

Note: You can check the output of the SENG Server to compare whether the Enclave measurements match the entries in the database whitelist.
The Enclave signer value is not yet used by the SENG Server.


### <a name="shadowsrv" /> Running the SENG Server with enabled Shadow Server (Experimental!)
Note: support for automatic creation of DNAT rules for SENG Runtime server sockets by
the Shadow Server is experimental and incomplete. Note that the SENG Runtime server
sockets will always be reachable through their Enclave IP(s) independent of the Shadow
Server. Furthermore, you can always manually setup NAT iptables rules for the Enclave IPs.
That means, **the Shadow Server is completely optional** and experimental at the moment.

If a SENG Runtime app with enabled port shadowing starts listening on a server socket
with port X, the Shadow Server will create DNAT rules for the host OUTPUT and PREROUTING 
nat tables to forward traffic targeting the *host* client IP and port X to the Enclave IP of the
SENG app. If port X is already in use by the client *host*, no rules will be added and the
listen call of the SENG app will fail with EADDRINUSE.
The Shadow Server communicates with a client-side helper tool for the detection of blocked host ports.

#### Preparation:
1. choose `192.168.28.0/24` as the only Enclave Subnetwork
2. create `"SENG_output"` and `"SENG_prerouting"` chains in the host/server iptables "nat" table:
    ```
    sudo iptables -t nat -N SENG_output
    sudo iptables -t nat -N SENG_prerouting
    sudo iptables -t nat -A OUTPUT -j SENG_output
    sudo iptables -t nat -A PREROUTING -j SENG_prerouting
    ```

    Note: you can optionally restrict the rules if you know the client host subnetwork(s) and/or
    port(s) in advance, e.g.:
    ```
    sudo iptables -t nat -A OUTPUT --dst 192.168.178.0/24 -p tcp --destination-port 4711 -j SENG_output
    sudo iptables -t nat -A PREROUTING --dst 192.168.178.0/24 -p tcp --destination-port 4711 -j SENG_prerouting
    ```

#### Run the SENG Server:
```
# [@seng-server]
cd ~/seng_server/double_tunnel_openssl/build/
sudo ./src/seng_ossl_double_tunnel_server -s 127.0.0.1 12345
```

Note: cf. [instructions for running NGINX inside the SENG Runtime with enabled Port
Shadowing](../seng_runtime/README.md#nginxshadow) for the client-side instructions.
