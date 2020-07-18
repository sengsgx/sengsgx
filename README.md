# SENG, the SGX-Enforcing Network Gateway

## Overview
SENG enables gateway firewalls to centrally enforce per--application policies.
SENG consists of the gateway-located SENG Server and two alternative client-side 
components: SENG Runtime and SENG SDK. While the client-side components shield
applications using Intel SGX, the SENG Server authenticates their network traffic and 
enables the gateway firewall to enforce rules on a per-app granularity.

The SENG repository is structured in the following way:
* `base_container/` -- contains the [Docker](https://www.docker.com/) files for the
SENG base container used for compiling [sgx-ra-tls](https://github.com/cloud-security-research/sgx-ra-tls)
and [Graphene-SGX](https://github.com/oscarlab/graphene)

* `benchmarking/` -- contains scripts and manifests for running and benchmarking a set of real-world apps
with the SENG Runtime

* `patches/` -- contains patch files for Graphene-SGX, sgx-ra-tls and [lwIP](https://savannah.nongnu.org/projects/lwip/)

* `sample_logs/` -- contains sample console outputs for each test/app

* `seng_runtime/` -- contains the client-side SENG Runtime based on the Graphene-SGX library OS

* `seng_sdk/` -- contains the client-side SENG SDK based on the [Intel SGX SDK](https://github.com/intel/linux-sgx)

* `seng_server/` -- contains the gateway-side SENG Server

* `tools/` -- currently only contains the Client Socket Blocker tool used for automatic DNAT
support for server sockets (optional)

We have also implemented the [SENG Netfilter](https://github.com/sengsgx/seng-netfilter) extension for SENG which integrates the per-application firewall rules of SENG into Netfilter/Xtables and iptables.
Support for SENG Netfilter is integrated into the SENG Server (cf. run instructions).
The SENG Netfilter extension components are provided as a [separate open source project](https://github.com/sengsgx/seng-netfilter).

## Documentation
The documentation is split across README.md files in all top-level subdirectories.
This (root) README.md serves as starting point and contains relative pointers to all sections relevant for building and running SENG in chronological order.

Note: for better readability (and clickable links), have a look at the HTML-parsed versions of the README.md files on Github at <https://github.com/sengsgx/sengsgx/blob/master/README.md>

Note(2): the relative pointers do not work on the new profile README of Github.
Visit the main [SENG repository](https://github.com/sengsgx/sengsgx).

### Research Paper
This repository belongs to a research project by [Fabian Schwarz](https://github.com/fa-schwarz) and Christian Rossow from the CISPA Helmholtz Center for Information Security.
The corresponding [research paper](https://publications.cispa.saarland/3119/1/seng-sec20.pdf) `"SENG, the SGX-Enforcing Network Gateway: Authorizing Communication from Shielded Clients"` will be published as part of the 29th USENIX Security Symposium (USENIX Security 20).
If you use SENG in a project, please cite using one of the formats provided by the export function of the [publication database](https://publications.cispa.saarland/3119/) or use the following bibtex entry:

```
@inproceedings{SENG2020,
    author = {Fabian Schwarz and Christian Rossow},
    title = {{SENG, the SGX-Enforcing Network Gateway: Authorizing Communication from Shielded Clients}},
    booktitle = {29th {USENIX} Security Symposium ({USENIX} Security 20)},
    year = {2020},
    address = {Boston, MA},
    publisher = {{USENIX} Association},
    month = aug,
    url = {https://publications.cispa.saarland/3119/}
}
```

## <a name="buildprep" /> Build Preparation
Note: All build instructions have been tested under **Ubuntu 16.04.6 LTS** and kernel 4.15.0-91.
The client-side has already been successfully tested with an older container version on
Ubuntu 18.04.2 LTS and kernel 4.15-0-47. [Docker](https://docs.docker.com/engine/install/ubuntu/)
and [Docker Compose](https://docs.docker.com/compose/install/) are required for building
and using the SENG development containers. We assume that the host user has been added to the `docker` group (`sudo usermod -aG docker $USER`) to run docker and docker-compose without sudo.

The following preparatory steps have to be performed **before building any** of the SENG components.

### <a name="spid" /> Getting SPID and SubscriptionKey for EPID-based Remote Attestation
SENG uses the EPID-based Intel SGX Remote Attestation Service (IAS) for attesting the
shielded applications. For using the IAS service, an Intel Developer Zone account is required
with development access to EPID-based Attestation:

1. If you have no account for the Intel Developer Zone, please register at <https://software.intel.com/registration/>
2. Login with your Intel Developer account at <https://api.portal.trustedservices.intel.com/EPID-attestation> and then subscribe to the "Development Access" for the EPID Intel SGX Attestation Service with linkable or unlinkable quotes (choose according to your needs/preferences).
    * Linkable:   <https://api.portal.trustedservices.intel.com/productes/dev-intel-software-guard-extensions-attestation-service-linkable>
    * Unlinkable: <https://api.portal.trustedservices.intel.com/productes/dev-intel-software-guard-extensions-attestation-service-unlinkable>

    Note: The links only work when logged in. Both links are given on the `/EPID-attestation` page. Choose "Development Access".
3. After successful registration/confirmation, go to your subscription management page at <https://api.portal.trustedservices.intel.com/developer> to get your SPID and SubscriptionKey(s) required for the remote attestation.

### Patching and Building sgx-ra-tls and Graphene-SGX
Next, we patch and build sgx-ra-tls and the Graphene-SGX library OS. The client-side uses
sgx-ra-tls to bind the enclave attestation report to the DTLS tunnel connection established
with the SENG Server.

1. pull submodules:
    `git submodule update --init --recursive`

    Note: If you downloaded the SENG archive (no git), clone the required submodules manually:
    ```
    # lwIP
    pushd seng_runtime/lwip_based_client_lib/externals/lwip/
    git clone https://git.savannah.nongnu.org/git/lwip.git .
    git checkout 2ff0db9a9b047d1c94ddbeea010561d1b9032101
    popd

    # sgx-ra-tls
    pushd sgx-ra-tls/
    git clone https://github.com/cloud-security-research/sgx-ra-tls .
    git checkout 10de7cc9ff8ffaebc103617d62e47e699f2fb5ff
    popd
    ```

2. patch sgx-ra-tls:
    ```
    cd sgx-ra-tls/
    patch -p1 < ../patches/sgx-ra-tls_seng_changes.patch
    ```

3. copy patch files for Graphene
    ```
    # copy graphene patch files
    cp ../patches/pull_request_438.patch \
       ../patches/graphene_patches.patch \
       ../patches/fixed_exitless_syscalls_pr405.patch \
       .
    ```

#### Configure Remote Attestation
Note: The steps for the remote attestation are only required if one of the client components
will be built (SENG Runtime or SDK).

4. If you do not have an SPID and SubscriptionKey for the EPID-based Intel SGX Remote
Attestation Service (IAS), please follow [the instructions above](#spid) to get them

5. add your own Intel Developer SPID to `sgx-ra-tls/ra_tls_options.c`

    e.g., if your SPID is 473BA3(...), add 0x47, 0x3B, 0xA3,(...)
6. adapt quote_type in `ra_tls_options.c` according to your quote type chosen for the
EPID remote attestation service:
    * (a) SGX_LINKABLE_SIGNATURE
    * (b) SGX_UNLINKABLE_SIGNATURE

7. add your own Intel Developer remote attestation subscription key to `sgx-ra-tls/ias-ra.c:211` by replacing the `"YYY"` with one of your two subscription keys

#### Build the SENG Base Container
Note: The base container will try to install headers for your host kernel version. Please use
a standard Linux kernel.

8. replace the container `userid` with your host UID (`id --user`) in `base_container/Dockerfile:11`
9. build base container:
    ```
    cd base_container/
    docker-compose build
    ```

#### Build sgx-ra-tls and Graphene using the Base Container (w/o exitless)
10. build sgx-ra-tls and Graphene-SGX:
    ```
    cd base_container/
    docker-compose run --user encl-dev base-container
    cd ~/sgx-ra-tls/
    ./build.sh graphene
    make
    ```

    Note: By default Graphene-SGX is built **without** the experimental exitless O/ECALL pull request, as it can be instable and cause bugs/crashes in Graphene.
    Higher thread pressure, e.g., caused by running all SENG components locally on the same host, particularly increases the instability of exitless calls.
    If you want to test the SENG Runtime with experimental support for exitless O/ECALLs, you have 2 options to enable it:

    * (a) remove the # in line 121 of the patched `sgx-ra-tls/build.sh` file before running it
    * (b) after step 10, patch and recompile Graphene-SGX manually:
        ```
        # [base-container]
        cd ~/sgx-ra-tls/deps/graphene/

        # enable exitless O/ECALLs (can be instable)
        patch -p1 < ../../fixed_exitless_syscalls_pr405.patch
        make SGX=1
        ```
    We recommend testing your setup first without the exitless feature.


#### Prepare SENG Server Certificate
The SENG Server requires an RSA key pair for the DTLS tunnel connection.
The certificate will be pinned by the SENG Runtime and SENG SDK.

11. generate RSA key pair for SENG Server:
    ```
    cd seng_server/
    openssl req -x509 -newkey rsa:3072 -keyout srv_key.pem -out srv_cert.pem -days 365 -nodes
    ```


## <a name="clibuildprep" /> Client-side Build Preparation
The following preparatory steps have to be performed **before building** any client-side
SENG component, including **the SENG Runtime and SENG SDK**. They are not required if
only the SENG Server component will be built.

1. Install Intel SGX driver at host
    ```
    sudo apt-get install linux-headers-$(uname -r)
    mkdir external/
    cd external/
    wget https://github.com/intel/linux-sgx-driver/archive/2a509c203533f9950fa3459fe91864051bc021a2.zip
    unzip \*.zip
    ```

    build and install (cf. shipped instructions for installation); for demo, e.g.:
    ```
    cd linux-sgx-driver-2a509c203533f9950fa3459fe91864051bc021a2/
    make
    sudo insmod isgx.ko
    ```
    Note: cf. driver readme for proper installation

2. Install Intel SGX PSW version 2.7.1 at host, e.g., for Ubuntu 16.04 LTS:
    ```
    cd external/
    wget https://download.01.org/intel-sgx/sgx-linux/2.7.1/distro/ubuntu16.04-server/libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb
    sudo dpkg -i ./libsgx-enclave-common_2.7.101.3-xenial1_amd64.deb
    ```

    check that `aesmd` is running:
    ```
    sudo service aesmd status
    ```
    `"/var/run/aesmd/aesm.socket"` should exist now


3. Install Graphene-SGX driver (legacy?) at host:
    ```
    sudo insmod sgx-ra-tls/deps/graphene/Pal/src/host/Linux-SGX/sgx-driver/graphene-sgx.ko
    sudo service aesmd restart
    ```
    Note: there is also a "load.sh" script, but it assumes proper installation of isgx.ko


## <a name="buildseng" /> Building the SENG Components
Each of the SENG components is built using a separate Docker container based on the SENG
base container. The build instructions for each component are provided in the README files
of the respective subdirectory:

* [build the SENG Server](seng_server/README.md#build)
* [build the SENG Runtime](seng_runtime/README.md#build)
* [build the SENG SDK](seng_sdk/README.md#build)



## <a name="runseng" /> Running and Benchmarking the SENG Components
Note that at the moment the SENG Runtime and SENG SDK have the SENG Server address and port hardcoded, and assume it to be `127.0.0.1:12345/udp`.
Please see the [respective SENG Server section](seng_server/README.md#serverdefault) for adapting it to your needs.
The default setup allows to run all tests on a single SGX-enabled machine.
However, it is intended to run the SENG Runtime/SDK on the client host, the SENG Server on the gateway host and 3rd party programs on the gateway or an external host if possible. See the [section below](#diffhosts) for multi-host configuration hints.
Also note that the SENG Server currently can have problems handling more than 1 enclave
at once (cf. [Limitations](#limitations) and [TODO.md](TODO.md)).
Restart in case of unexpected problems and refer to the notes in the respective sections.

**CAUTION**: the loopback destination address `127.0.0.1` is currently **NOT** supported *through*(!) the lwIP tunnel as lwIP will interpret and refuse it internally (cf. todos).
For local tests, use your internal host IP instead (cf. respective run instructions).


### <a name="rundemos" /> Running the SENG Components and Demo Apps
The SENG Runtime and SENG SDK both ship with a small Demo Application for testing the setup.
The instructions for running the SENG components and Demo Apps are provided in the README files of the respective subdirectories:

* [run the SENG Server](seng_server/README.md#run)
* [run the SENG Runtime and its Demo App](seng_runtime/README.md#run)
* [run the SENG SDK and its Demo App](seng_sdk/README.md#run)



### <a name="runapps" /> Running and Benchmarking the Real-world Apps with SENG
The SENG Runtime and SENG SDK ship with scripts for running and benchmarking a set of real-world applications.
The SENG Runtime supports running iPerf3, cURL, Telnet and NGINX, while the SENG SDK ships with a ported version of NGINX.
The instructions for building, running and benchmarking the real-world apps with the SENG Runtime and SENG SDK are provided in the README files of the respective subdirectory:

* [run and benchmark the SENG Runtime real-world apps](seng_runtime/README.md#bench)
* [run and benchmark the SENG SDK port of NGINX](seng_sdk/README.md#bench)



### Running the Setup/Initialization Microbenchmarks
Two microbenchmarks are provided which measure the initialization time of (i) Graphene-SGX and of (ii) the SENG Runtime.
The instructions for preparing and running the microbenchmarks are provided in the [README file of the SENG Runtime](seng_runtime/README.md#mbench).


### <a name="diffhosts" /> Hints for Running SENG Server and Client(s) on separate Hosts
The default instructions allow testing SENG locally on a single SGX-enabled machine.
For running the SENG Server on a separate gateway host, you currently must manually adapt the hardcoded SENG Server IP addresses in the SENG Runtime and SENG SDK as described in the [SENG Server section](seng_server/README.md#serverdefault).
Ensure that you share the correct SENG Server public key with the SENG Runtime/SDK hosts.
When testing the demo and real-world apps in this setup, the easiest way is to run the 3rd party client/server tools (e.g., netcat) on the gateway host.
If you want to run the 3rd party tools on separate external hosts, you must use port forwarding (NAT) rules on the gateway to make the Enclaves reachable for them. In addition, for "native" and "pure" benchmarking, you must ensure that all traffic passes through the gateway server (in both directions!) by using additional NATing (@gateway) and/or routing rules (@clients).


## <a name="limitations" /> Limitations
The current protoype has a number of limitations, including:
* SENG Server IP and Port are hardcoded in the SENG Runtime and SENG SDK
* IAS IP currently hardcoded in trusted hosts file (only for SENG Runtime initialization code)
* instead of internal server/gateway, the client enclaves currently connect to IAS
* the SENG Server can have problems handling multiple Enclaves, because of its current reliance on SO_REUSEPORT
* SQLite3 database support, but no thorough database integration yet
* SENG Server does not yet check Enclave attributes and/or mr_signer
* SENG Server does not yet actively clean conntrack entries before re-assigning an Enclave IP
* instable Graphene-SGX exitless O/ECALLs
* loopback destination IP (127.0.0.1) through(!) the tunnel is not yet working, because lwIP interprets and refuses such traffic internally
* missing shutdown API for SENG SDK
* SENG SDK uses/has no fs-shield yet

See [TODO.md](TODO.md) for a general list of todos, planned features and co.
