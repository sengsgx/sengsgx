## Todos, Limitations and Planned Features

The following is a list of unordered todos.

### General
* make SENG Server IP and Port easier configurable at SENG Runtime and SENG SDK
* consider porting to new versions of Graphene-SGX and sgx-ra-tls
* containers without "host" networking mode and with least privilege


### SENG client components
* loopback destination IP (127.0.0.1) through(!) the tunnel is not yet working, because lwIP interprets and refuses such traffic internally
* IPv6 support [also SENG Server]
* lwIP's limited service port resolution
* at the moment the DNS server used by lwIP for standard APIs, e.g., getaddrinfo(), is hardcoded in the SENG Runtime/SDK startup code (to 8.8.8.8)


### SENG Server
* the SENG Server currently can have problems handling multiple Enclaves, because its current use of SO_REUSEPORT causes problems if newly connecting Enclaves are not bound to the fresh welcome socket by the kernel (cf. discussion in `SengServer_OpenSSL.cpp`)
* option to only build the minimum of sgx-ra-tls required for the SENG server


### SENG Runtime
* remove SENG-dependencies from "pure" manifest files
* don't link shadow socket files if auto-nat/listen shadowing is disabled
* fix NGINX termination
* IAS IP currently hardcoded in trusted hosts file (only affects initialization code)


### Port Shadowing / Automatic NAT [optional, experimental]
* Runtime: remove hardcoded ShadowServer IP and make it instead use the SENG tunnel interface IP(s)
* Server: finish support for automatic cleanup of shadowing rules on a server socket close
* Cli.Tool: add user/system access policy support in client helper tool
* port ShadowServer and Cli.Tool from mbedTLS to OpenSSL


### SENG SDK
* currently SDK and PSW are installed inside the container, i.e., on restarts/reinstantiation, both are gone again; temporary work-arounded by adding the option to cause a direct re-install on container session start if it has been compiled before
* shutdown API for SENG SDK (requires lwIP + tunnel thread termination)
* add support to SENG NGINX to change SENG Server IP+Port via NGINX config file
* SENG SDK uses/has no fs-shield yet
