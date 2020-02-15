#include <stdio.h>
#include <pthread.h>

#include "seng_threads_u.h"

//#define PORT_OCALL_DEBUG

extern sgx_enclave_id_t global_eid;

static void *run_seng_thread(void *arg) {
    (void)(arg); // UNUSED
#ifdef PORT_OCALL_DEBUG
    printf("%s called\n", __PRETTY_FUNCTION__);
#endif
    int res = -1;
    sgx_status_t status = start_new_seng_thread(global_eid, &res);
    if (status != SGX_SUCCESS || res != 0) {
        // happens e.g., on enclave destroy in the end
        if ( status == SGX_ERROR_ENCLAVE_LOST || status == SGX_ERROR_ENCLAVE_CRASHED) {}
        else {
            printf("Failed starting new SENG thread, trusted thread will time out\n");
            printf("status = %d, ret = %d\n", status, res);
        }
    }
}

int create_new_seng_thread(const char *name) {
#ifdef PORT_OCALL_DEBUG
    printf("%s called\n", __PRETTY_FUNCTION__);
#endif
    pthread_t t;
    int ret = pthread_create(&t, NULL, run_seng_thread, NULL);
    if (ret == 0 && name) {
        pthread_setname_np(t, name);
    }
}
