#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#define LWIP_UNIX_LINUX

#include <tlibc/sys/endian.h>

// adding SSIZE_MAX definition to prevent lwIP from redefining ssize_t as int
#ifndef SSIZE_MAX
typedef long int ssize_t;
#define SSIZE_MAX  ((((ssize_t) 0x7fffffffL) << 32) | 0xffffffffL)
#endif /* SSIZE_MAX */

// TODO: not available in SGX SDK --> could use header of SGXSSL instead of lwIP's
//#define LWIP_TIMEVAL_PRIVATE 0
//#include <sys/time.h>

#define LWIP_ERRNO_INCLUDE <errno.h>
#define LWIP_ERRNO_STDINCLUDE	1

// libc:  int rand(void); -- return a value between 0 and RAND_MAX (inclusive)
// sgx_status_t sgx_read_rand(unsigned char *rand, size_t length_in_bytes);
unsigned int seng_rand(void);
#define LWIP_RAND() ((u32_t)seng_rand())

//int fflush(void *);

/* different handling for unit test, normally not needed */
#ifdef LWIP_NOASSERT_ON_ERROR
#define LWIP_ERROR(message, expression, handler) do { if (!(expression)) { \
  handler;}} while(0)
#endif

struct sio_status_s;
typedef struct sio_status_s sio_status_t;
#define sio_fd_t sio_status_t*
#define __sio_fd_t_defined

typedef unsigned int sys_prot_t;

#endif /* LWIP_ARCH_CC_H */
