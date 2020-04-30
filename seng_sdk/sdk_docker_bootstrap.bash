#!/bin/bash
if [ ! -d "/opt/intel/" ]; then
    echo "Note: /opt/intel/ is missing"

    if [ -d ~/seng_sdk/external/linux-sgx-sgx_2.7.1/ ]; then
        echo "Note: SDK-PSW seems to have been downloaded"
        read -p "Try re-install? (Y/n) " choice
        REINSTALL=false
        case $choice in
            [Yy]* )
                REINSTALL=true;
                ;;
            [Nn]* )
                ;;
            *)
                REINSTALL=true;
                ;;
        esac
        if $REINSTALL; then
            pushd ~/seng_sdk/;
            ./reinstall_patched_sdkpsw_sgxssl.bash;
            popd;
        fi
    fi
fi
/bin/bash
