#ifndef SENG_THREADS_U_H__
#define SENG_THREADS_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _seng_timespec
#define _seng_timespec
typedef struct seng_timespec {
	long int tv_sec;
	long int tv_nsec;
} seng_timespec;
#endif

#ifndef CREATE_NEW_SENG_THREAD_DEFINED__
#define CREATE_NEW_SENG_THREAD_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, create_new_seng_thread, (const char* name));
#endif
#ifndef SENG_CLOCK_GETTIME_DEFINED__
#define SENG_CLOCK_GETTIME_DEFINED__
int SGX_UBRIDGE(SGX_NOCONVENTION, seng_clock_gettime, (int clk_id, struct seng_timespec* tp));
#endif

sgx_status_t start_new_seng_thread(sgx_enclave_id_t eid, int* retval);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
