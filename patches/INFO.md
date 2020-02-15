SGX-RA-TLS patches are applicable to:
        10de7cc9ff8ffaebc103617d62e47e699f2fb5ff

Graphene-SGX:
graphene_patches are applied as part of `build.sh graphene` by sgx-ra-tls
to 58cb88d2c187358aad428b100d1ff444173e1a2b (after sgx-ra-tls patch)

BUT(!): exitless syscall patch (fixed_exitless_syscalls_pr405.patch)  currently
has to be applied manually afterwards inside graphene-sgx director! (sgx-ra-tls/deps/graphene/)

lwIP patch total_lwip_patcher.patch has to be manually applied to
        2ff0db9a9b047d1c94ddbeea010561d1b9032101       
