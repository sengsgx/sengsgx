#ifndef DEMO_APP_H
#define DEMO_APP_H

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

// Based on Switchless SDK Sample Code

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

# define TOKEN_FILENAME   "app_enclave.token"
# define TESTENCLAVE_FILENAME "../../../enclave/app/src/app_enclave.signed.so"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#endif /* !DEMO_APP_H */
