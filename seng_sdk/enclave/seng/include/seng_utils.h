#ifndef SENG_T_RUNTIME_H
#define SENG_T_RUNTIME_H

#include "tSgxSSL_api.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifdef __GNUC__
    #define likely(x)       __builtin_expect(!!(x), 1)
    #define unlikely(x)     __builtin_expect(!!(x), 0)
#else
    #define likely(x)       (x)
    #define unlikely(x)     (x)
#endif

void printf(const char *fmt, ...);
int vprintf_cb(Stream_t, const char *, va_list);

#if defined(__cplusplus)
}
#endif

#endif /* !SENG_U_RUNTIME_H */