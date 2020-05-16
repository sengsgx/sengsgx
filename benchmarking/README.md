## Benchmarking

This directory contains scripts and manifest files for downloading, running and benchmarking a set of real-world applications inside the SENG Runtime.
Please refer to the detailed instructions in the [SENG Runtime README file](../seng_runtime/README.md#bench).
For running and benchmarking the SENG SDK port of NGINX, please refer to the corresponding section in the [SENG SDK README](../seng_sdk/README.md#bench).

Apps:
* `curl/` -- scripts and manifests for running `cURL 7.47.0` inside the SENG Runtime
* `iperf3/` -- scripts and manifests for running `iPerf 3.1.3` inside the SENG Runtime
* `nginx/` -- scripts and manifests for running `NGINX 1.10.3` inside the SENG Runtime
* `telnet/` -- scripts and manifests for running `Telnet 0.17-40` (apt) inside the SENG Runtime

Misc:
* `patches/` -- contains patch file for iPerf3 client to close sockets on errors, s.t. the iPerf3 server does not hang forever
