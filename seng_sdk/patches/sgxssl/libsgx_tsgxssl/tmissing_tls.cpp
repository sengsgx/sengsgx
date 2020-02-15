#include <string.h>

#include "sgx_tsgxssl_t.h"
#include "tcommon.h"


extern "C" {

/* Add missing ones popping up because of SSL/TLS */
int sgxssl_shutdown(int sockfd, int how)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}

// note: replaced DIR* with void*
struct dirent *sgxssl_readdir(void *dirp)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return NULL;
}

void *sgxssl_opendir(const char *name)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return NULL;
}

int sgxssl_closedir(void *dirp)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}

int sgxssl_stat(const char *pathname, struct stat *statbuf)
{
    FSTART;

    SGX_UNREACHABLE_CODE(SET_ERRNO);

    FEND;

    return -1;
}
}
