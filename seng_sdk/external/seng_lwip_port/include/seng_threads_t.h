#ifndef SENG_THREADS_T_H__
#define SENG_THREADS_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


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

int start_new_seng_thread(void);

sgx_status_t SGX_CDECL create_new_seng_thread(int* retval, const char* name);
sgx_status_t SGX_CDECL seng_clock_gettime(int* retval, int clk_id, struct seng_timespec* tp);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
