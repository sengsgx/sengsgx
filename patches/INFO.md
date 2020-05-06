## SGX-RA-TLS patch
sgx-ra-tls_seng_changes.patch must be manually applied to commit 10de7cc9ff8ffaebc103617d62e47e699f2fb5ff

## Graphene-SGX:
* pull_request_438.patch is applied as part of `build.sh graphene` (after patching sgx-ra-tls)
	source: https://github.com/oscarlab/graphene/pull/438

* graphene_patches.patch is applied as part of `build.sh graphene` (after patching sgx-ra-tls)

* fixed_exitless_syscalls_pr405 can be manually applied
	source: https://github.com/oscarlab/graphene/pull/405

All are compatible with Graphene commit 58cb88d2c187358aad428b100d1ff444173e1a2b

## lwIP patch
total_lwip_patcher.patch must be manually applied to commit 2ff0db9a9b047d1c94ddbeea010561d1b9032101

