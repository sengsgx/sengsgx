#!/bin/bash
# socat tunnel to aesmd required to sgx enclaves
socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &
/bin/bash
