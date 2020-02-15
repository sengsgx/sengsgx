#include "hooks/getinfo.hpp"

#include "HookCommons.hpp"

#include <lwip/netdb.h>


void init_getinfo_hooks(void *libc_handle) {
    real_getsockname = (int (*)(int, struct sockaddr *, socklen_t *)) dlsym(libc_handle, "getsockname");
    if(unlikely(real_getsockname == nullptr)) throw std::runtime_error("dlsym(getsockname) failed");
    
    real_getpeername = (int (*)(int, struct sockaddr *, socklen_t *)) dlsym(libc_handle, "getpeername");
    if(unlikely(real_getpeername == nullptr)) throw std::runtime_error("dlsym(getpeername) failed");

    real_getaddrinfo = (int (*)(const char *, const char *, const struct addrinfo *, struct addrinfo **)) dlsym(libc_handle, "getaddrinfo");
    if(unlikely(real_getaddrinfo == nullptr)) throw std::runtime_error("dlsym(getaddrinfo) failed");
    
    real_freeaddrinfo = (void (*)(struct addrinfo *)) dlsym(libc_handle, "freeaddrinfo");
    if(unlikely(real_freeaddrinfo == nullptr)) throw std::runtime_error("dlsym(freeaddrinfo) failed");
}

int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked getsockname(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_getsockname(sockfd, addr, addrlen);
    }
    assert(real_getsockname != nullptr);
    return real_getsockname(sockfd, addr, addrlen);
}

int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked getpeername(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_getpeername(sockfd, addr, addrlen);
    }
    assert(real_getpeername != nullptr);
    return real_getpeername(sockfd, addr, addrlen);
}

int seng_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
#ifdef DEBUG_PRINT
    printf("seng_getaddrinfo()\n");
    fflush(stdout);
#endif
    assert(real_getaddrinfo != nullptr);
    return real_getaddrinfo(node, service, hints, res);
}

int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
#ifdef DEBUG_PRINT
    printf("Hooked getaddrinfo('%s', '%s', %p, %p)\n", node, service, hints, res);
    if (hints != nullptr) {
        printf("hints = {\nai_flags = %d,\nai_family = %d,\nai_socktype = %d,\nai_protocol = %d,\nai_addrlen = %d,\nai_addr = %p,\n ai_canonname = %s,\nai_next = %p\n}\n", hints->ai_flags, hints->ai_family, hints->ai_socktype, hints->ai_protocol, hints->ai_addrlen, hints->ai_addr, hints->ai_canonname, hints->ai_next);
    }
    fflush(stdout);
#endif
    auto resturn_val = lwip_getaddrinfo(node, service, hints, res);
#ifdef DEBUG_PRINT
    auto safe = errno;
    printf("lwip_getaddrinfo() returned %d\n", resturn_val);
    // gai_strerror(..)
    errno = safe;
#endif
    return resturn_val;
}

void seng_freeaddrinfo(struct addrinfo *res) {
#ifdef DEBUG_PRINT
    printf("seng_freeaddrinfo()\n");
    fflush(stdout);
#endif
    assert(real_freeaddrinfo != nullptr);
    return real_freeaddrinfo(res);
}

void freeaddrinfo(struct addrinfo *res) {
#ifdef DEBUG_PRINT
    printf("Hooked freeaddrinfo()\n");
    fflush(stdout);
#endif
    return lwip_freeaddrinfo(res);
}

