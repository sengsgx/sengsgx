#ifndef SENG_HOOKS_GETINFO_HPP
#define SENG_HOOKS_GETINFO_HPP

#include <unistd.h> // might introduce lwip-inconsistent socklen_t definition?

/* Shadowing Socket API functions */
extern "C" {    // avoids name mangling
    int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    
    
    int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    void freeaddrinfo(struct addrinfo *res);
    
    /* Trampoline Functions to "real" [libc] functions */
    int seng_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
    
    void seng_freeaddrinfo(struct addrinfo *res);
}

/* Function Pointers to "real" [libc] Socket API functions */
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *);

static int (*real_getaddrinfo)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
static void (*real_freeaddrinfo)(struct addrinfo *);

void init_getinfo_hooks(void *libc_handle);

#endif /* SENG_HOOKS_GETINFO_HPP */
