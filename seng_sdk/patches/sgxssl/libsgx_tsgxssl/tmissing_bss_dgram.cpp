#include "sgx_tsgxssl_t.h"
#include "tcommon.h"
#include "tSgxSSL_api.h"

#include "sgx_edger8r.h"

#include <stdio.h>
#include <string.h>

extern PRINT_TO_STDOUT_STDERR_CB s_print_cb;

extern "C" {

/* Add missing ones popping up because of bss_dgram -- BIO_new_dgram(..) */
size_t sgxssl_sendto(int sockfd, const void *buf, size_t len, int flags)
{
    FSTART;

/*
           size_t ret = -1;
//           seng_read (&ret, fd, buf, count);
           u_direct_read (&ret, fd, buf, count);
           return ret;
*/

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}

long int sgxssl_recv(int sockfd, void *buf, size_t len, int flags)
{
    FSTART;

    void *u_buf = sgx_ocalloc(len);
    if (u_buf == NULL) abort();

    long int ret = -1;
    u_direct_recv( &ret, sockfd, u_buf, len, flags);

    // Only if successful ++ <= len, copy from untrusted
    if (ret <= 0) return ret;
    if (((size_t)ret) > len) abort();

    // TODO: do I need an !sgx_is_outside_enclave() here?
    // no, I don't think so

    memcpy(buf, u_buf, ret);
    sgx_ocfree();
    return ret;


/*
    long int ret = -1;
    u_direct_recv (&ret, sockfd, buf, len, flags);
    return ret;
*/  
    
    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}


size_t sgxssl_recvfrom(int sockfd, void *buf, size_t len, int flags,
                        struct sockaddr *src_addr, socklen_t *addrlen)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}

// TODO: emulate
void sgxssl_perror(const char *s)
{
    FSTART;

	if (s_print_cb != NULL) {
        char buf[256];
        snprintf(buf, sizeof(buf), "%s: <tba> [errno: %d]\n", s, errno);

        // how empty one?!
		va_list vl;
		s_print_cb(STREAM_STDERR, buf, vl);
		va_end(vl);
	}

    FEND;
}

}
