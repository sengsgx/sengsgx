#ifndef SENG_HOOK_COMMONS_HPP
#define SENG_HOOK_COMMONS_HPP

#include <stdexcept>

#include <cstdio>
#include <cassert>

#include <dlfcn.h>

#include <lwip/sockets.h>

#define unsupported_SOCK_CLOEXEC (02000000)

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

//#define DEBUG_PRINT

#endif /* #ifndef SENG_HOOK_COMMONS_HPP */

