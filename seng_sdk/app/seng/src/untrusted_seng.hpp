#ifndef U_SENG_HPP
#define U_SENG_HPP

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

extern sgx_enclave_id_t global_eid;    /* global enclave id */

extern "C" {
    int setup_tunnel_socket(short port, const char *dst_ip);
}

#endif /* !U_SENG_HPP */