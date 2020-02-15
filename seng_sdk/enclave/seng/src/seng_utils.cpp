#include "seng_utils.h"
#include "seng_t.h"

#include <stdio.h> // vsnprintf


#define TEST_CHECK(status)  \
    {   \
            if (status != SGX_SUCCESS) {    \
                        printf("OCALL status check failed %s(%d), status = %d\n", __FUNCTION__, __LINE__, status);  \
                        abort();    \
                    }   \
    }

int vprintf_cb(Stream_t stream, const char * fmt, va_list arg)
{
       char buf[BUFSIZ] = {'\0'};

       int res = vsnprintf(buf, BUFSIZ, fmt, arg);
       if (res >=0) {
               sgx_status_t sgx_ret = uprint((const char *) buf);
               TEST_CHECK(sgx_ret);
       }
       return res;
}

/* 
 * printf: 
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    uprint(buf);
}