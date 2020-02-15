#include "hooks/sockets.hpp"
#include "hooks/listen_shadow.hpp"

#include "HookCommons.hpp"

//#define ENABLE_LISTEN_MECHANISM
// -D ENABLE_LISTEN_MECHANISM
// target_compile_definitions(...)

//#define MEASURE_LISTEN_TIME
// target_compile_definitions(...)


void init_sockets_hooks(void *libc_handle) {
    if(unlikely(libc_handle == nullptr)) throw std::runtime_error("libc_handle is nullptr");
    
    real_socket = (int (*)(int,int,int)) dlsym(libc_handle, "socket");
    if(unlikely(real_socket == nullptr)) throw std::runtime_error("dlsym(socket) failed");
    
    real_connect = (int (*)(int, const struct sockaddr *, socklen_t)) dlsym(libc_handle, "connect");
    if(unlikely(real_connect == nullptr)) throw std::runtime_error("dlsym(connect) failed");
    
    real_bind = (int (*)(int, const struct sockaddr *, socklen_t)) dlsym(libc_handle, "bind");
    if(unlikely(real_bind == nullptr)) throw std::runtime_error("dlsym(bind) failed");
    
    real_listen = (int (*)(int, int)) dlsym(libc_handle, "listen");
    if(unlikely(real_listen == nullptr)) throw std::runtime_error("dlsym(listen) failed");
    
    real_accept = (int (*)(int, struct sockaddr *, socklen_t *)) dlsym(libc_handle, "accept");
    if(unlikely(real_accept == nullptr)) throw std::runtime_error("dlsym(accept) failed");
    
    real_accept4 = (int (*)(int, struct sockaddr *, socklen_t *, int)) dlsym(libc_handle, "accept4");
    if(unlikely(real_accept4 == nullptr)) throw std::runtime_error("dlsym(accept4) failed");
    
    real_close = (int (*)(int)) dlsym(libc_handle, "close");
    if(unlikely(real_close == nullptr)) throw std::runtime_error("dlsym(close) failed");
    
    real_shutdown = (int (*)(int, int)) dlsym(libc_handle, "shutdown");
    if(unlikely(real_shutdown == nullptr)) throw std::runtime_error("dlsym(shutdown) failed");
}

int seng_socket(int domain, int type, int protocol) {
#ifdef DEBUG_PRINT
    printf("seng_socket()\n");
    fflush(stdout);
#endif
    assert(real_socket != nullptr);
    return real_socket(domain, type, protocol);
}

int socket(int domain, int type, int protocol) {
#ifdef DEBUG_PRINT
    printf("Hooked socket(%d, %d, %d)\n", domain, type, protocol);
    fflush(stdout);
#endif
    /*
     * Linux allows to OR SOCK_NONBLOCK (O_NONBLOCK) and SOCK_CLOEXEC (O_CLOEXEC) to type;
     * lwIP does NOT allow that, BUT at least lwIP can support O_NONBLOCK via usual lwip_fcntl();
     * so strip O_CLOEXEC with warning, and perform O_NONBLOCK mode setting manually
     */
    auto sockfd = lwip_socket(domain,
                              type & (0xffffffff ^ unsupported_SOCK_CLOEXEC ^ O_NONBLOCK), // strip the 2 flags
                              protocol);
    auto safe = errno;
#ifdef DEBUG_PRINT
    printf("lwip_socket has returned with %d\n", sockfd);
    fflush(stdout);
#endif
    if(unlikely(sockfd < LWIP_SOCKET_OFFSET && sockfd != -1)) throw std::runtime_error("lwip_socket() returned FD from wrong range");
    
    // set nonblock manually if requested
    if(unlikely (type & O_NONBLOCK) != 0 ) {
#ifdef DEBUG_PRINT
        printf("manually setting nonblock flags\n");
        fflush(stdout);
#endif
        // TODO: should we close on failure?
        int ret = lwip_fcntl(sockfd, F_SETFL, O_NONBLOCK);
        assert( ret == 0 );
    }
    errno = safe;
    return sockfd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked connect(%d, addrlen=%d)\n", sockfd, addrlen);
    if (addrlen > 0 && addr != nullptr) {
        printf("addr->sa_family: %d\n", addr->sa_family);
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *p = (const struct sockaddr_in*)addr;
            printf("port: %d\n", lwip_ntohs(p->sin_port));
            printf("ip: %s\n", inet_ntoa(p->sin_addr));
        }
    }
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
#ifdef DEBUG_PRINT
        printf("Calling lwip_connect()\n");
        fflush(stdout);
#endif
        auto ret = lwip_connect(sockfd, addr, addrlen);
        auto safe = errno;
#ifdef DEBUG_PRINT
        printf("Returning FROM lwip_connect()\n");
        fflush(stdout);
#endif
        errno = safe;
        return ret;
    }
    assert(real_connect != nullptr);
    return real_connect(sockfd, addr, addrlen);
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked bind(%d)\n", sockfd);
    if (addrlen > 0 && addr != nullptr) {
        printf("addr->sa_family: %d\n", addr->sa_family);
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *p = (const struct sockaddr_in*)addr;
            printf("port: %d\n", lwip_ntohs(p->sin_port));
            printf("ip: %s\n", inet_ntoa(p->sin_addr));
        }
    }
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_bind(sockfd, addr, addrlen);
        auto safe = errno;
#ifdef DEBUG_PRINT
        printf("Returning FROM lwip_bind()\n");
        fflush(stdout);
#endif
        errno = safe;
        return ret;
    }
    assert(real_bind != nullptr);
    return real_bind(sockfd, addr, addrlen);
}

int listen(int sockfd, int backlog) {
#ifdef DEBUG_PRINT
    printf("Hooked listen()\n");
    printf("sockfd: %d\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        int res;
#ifdef MEASURE_LISTEN_TIME
        bool timeofday_ok {true};
        struct timeval listen_tv_start {}, listen_tv_end {};
        if( gettimeofday(&listen_tv_start, nullptr) != 0 ) {
            fprintf(stderr, "gettimeofday failed in listen\n");
            fflush(stderr);
            timeofday_ok = false;
        }
#endif
#ifdef ENABLE_LISTEN_MECHANISM
        // might execute listen-mechanism
        res = seng::request_listen_shadowing(sockfd, backlog);
#else
        res = lwip_listen(sockfd, backlog);
#endif
#ifdef MEASURE_LISTEN_TIME
        if( timeofday_ok ) {
            if ( gettimeofday(&listen_tv_end, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in listen\n");
                fflush(stderr);
            } else {
                auto diff_sec = listen_tv_end.tv_sec - listen_tv_start.tv_sec;
                auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end.tv_usec - listen_tv_start.tv_usec;
                printf("listen_time_in_usec;%ld\n", total_diff_in_ms);
                fflush(stdout);
            }
        }
#endif
        return res;
    }
    assert(real_listen != nullptr);
    return real_listen(sockfd, backlog);
}

int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked accept()\n");
    printf("sockfd: %d\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_accept(sockfd, addr, addrlen);
    }
    assert(real_accept != nullptr);
    return real_accept(sockfd, addr, addrlen);
}

int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked accept4()\n");
    printf("sockfd: %d\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_accept(sockfd, addr, addrlen);
        auto safe = errno;
        // set nonblock manually if requested
        if(unlikely ((flags & O_NONBLOCK) != 0 && ret >= 0) ) {
#ifdef DEBUG_PRINT
            printf("manually setting nonblock flags\n");
            fflush(stdout);
#endif
            // TODO: what to do on failure?
            int tmp = lwip_fcntl(ret, F_SETFL, O_NONBLOCK);
            assert( tmp == 0 );
        }
        errno = safe;
        return ret;
    }
    assert(real_accept4 != nullptr);
    return real_accept4(sockfd, addr, addrlen, flags);
}

int close(int fd) {
#ifdef DEBUG_PRINT
    printf("Hooked close(%d)\n", fd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
#ifdef ENABLE_LISTEN_MECHANISM
        seng::notify_listen_close(fd);
#endif
        return lwip_close(fd);
    }
    assert(real_close != nullptr);
    return real_close(fd);
}

int shutdown(int sockfd, int how) {
#ifdef DEBUG_PRINT
    printf("Hooked shutdown(%d, %d)\n", sockfd, how);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_shutdown(sockfd, how);
    }
    assert(real_shutdown != nullptr);
    return real_shutdown(sockfd, how);
}
