#include "hooks/sockctrl.hpp"

#include "HookCommons.hpp"


void init_sockctrl_hooks(void *libc_handle) {
    real_ioctl = (int (*)(int, unsigned long, va_list)) dlsym(libc_handle, "ioctl");
    if(unlikely(real_ioctl == nullptr)) throw std::runtime_error("dlsym(ioctl) failed");

    real_fcntl = (int (*)(int, int, ...)) dlsym(libc_handle, "fcntl");
    if(unlikely(real_fcntl == nullptr)) throw std::runtime_error("dlsym(fcntl) failed");
    
    real_getsockopt = (int (*)(int, int, int , void *, socklen_t *)) dlsym(libc_handle, "getsockopt");
    if(unlikely(real_getsockopt == nullptr)) throw std::runtime_error("dlsym(getsockopt) failed");
    
    real_setsockopt = (int (*)(int, int, int, const void *, socklen_t)) dlsym(libc_handle, "setsockopt");
    if(unlikely(real_setsockopt == nullptr)) throw std::runtime_error("dlsym(setsockopt) failed");
    
    real_sockatmark = (int (*)(int)) dlsym(libc_handle, "sockatmark");
    if(unlikely(real_sockatmark == nullptr)) throw std::runtime_error("dlsym(sockatmark) failed");
    
    real_isfdtype = (int (*)(int, int)) dlsym(libc_handle, "isfdtype");
    if(unlikely(real_isfdtype == nullptr)) throw std::runtime_error("dlsym(isfdtype) failed");
    
    real_dup = (int (*)(int)) dlsym(libc_handle, "dup");
    if(unlikely(real_dup == nullptr)) throw std::runtime_error("dlsym(dup) failed");

    real_dup2 = (int (*)(int, int)) dlsym(libc_handle, "dup2");
    if(unlikely(real_dup2 == nullptr)) throw std::runtime_error("dlsym(dup2) failed");
    
    real_dup3 = (int (*)(int, int, int)) dlsym(libc_handle, "dup3");
    if(unlikely(real_dup3 == nullptr)) throw std::runtime_error("dlsym(dup3) failed");
}

int ioctl(int fd, unsigned long request, va_list args) {
#ifdef DEBUG_PRINT
    printf("Hooked ioctl(%d, %#lx)\n", fd, request);
    printf("FIONREAD: %#x\n", FIONREAD);
    printf("FIONBIO: %#x\n", FIONBIO);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
#ifdef DEBUG_PRINT
        printf("Going to call lwip_ioctl()\n");
        fflush(stdout);
#endif
        //auto ret = lwip_ioctl(fd, request, va_arg(args, void *));
        auto ret = lwip_ioctl(fd, request, args);
        auto safe = errno;
#ifdef DEBUG_PRINT
        printf("lwip_ioctl() returned with %d, and %d\n", ret, *((int *)args));
        fflush(stdout);
#endif
        errno = safe;
        return ret;
    }
    assert(real_ioctl != nullptr);
    return real_ioctl(fd, request, args);
}

int fcntl(int fd, int cmd, ...) {
#ifdef DEBUG_PRINT
    printf("Hooked fcntl(%d, %d);\t\t", fd, cmd);
    printf("F_GETFL: %#x, F_SETFL: %#x\n", F_GETFL, F_SETFL);
    fflush(stdout);
#endif
    va_list args;
    va_start(args, cmd);
    
    // if from lwIP fd range
    // netif tunnel seems to call it very often, so optimize for it
    if (unlikely(fd >= LWIP_SOCKET_OFFSET)) {
#ifdef DEBUG_PRINT
        printf("Going to call lwip_fcntl()\n");
        fflush(stdout);
#endif
        int ret;
        switch(cmd) {
            case F_SETFL:
            {
#ifdef DEBUG_PRINT
                printf("Trying to get flags value with va_arg(args,int)\n");
                fflush(stdout);
#endif
                int flags = va_arg(args, int);  // works
#ifdef DEBUG_PRINT
                printf("Got it! (%d)\n", flags);
                fflush(stdout);
#endif
                // lwIP only supports O_NONBLOCK for F_SETFL; it auto-strips access-related flags
#ifdef DEBUG_PRINT
                printf("Calling lwip_fcntl(%d, F_SETFL, %d) now\n", fd, flags);
                fflush(stdout);
#endif
                ret = lwip_fcntl(fd, F_SETFL, flags);
                break;
            }
            case F_GETFL:
                ret = lwip_fcntl(fd, F_GETFL, 0);
                break;
            default:
                fprintf(stderr, "Only F_S/GETFL supported by lwIP\n");
                errno = EINVAL;
                return -1;
        }
        auto safe = errno;
#ifdef DEBUG_PRINT
        printf("lwip_fcntl() returned with %d\n", ret);
        fflush(stdout);
#endif
        va_end(args);
        errno = safe;
        return ret;
    }
    assert(real_fcntl != nullptr);
    int ret = real_fcntl(fd, cmd, args);    // works
    va_end(args);
    return ret;
}

int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
#ifdef DEBUG_PRINT
    printf("Hooked getsockopt(%d, %d, %d)\n", sockfd, level, optname);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_getsockopt(sockfd, level, optname, optval, optlen);
    }
    assert(real_getsockopt != nullptr);
    return real_getsockopt(sockfd, level, optname, optval, optlen);
}

int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
#ifdef DEBUG_PRINT
    printf("Hooked setsockopt(%d, %d, %d)\n", sockfd, level, optname);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_setsockopt(sockfd, level, optname, optval, optlen);
    }
    assert(real_setsockopt != nullptr);
    return real_setsockopt(sockfd, level, optname, optval, optlen);
}

int sockatmark(int sockfd) {
#ifdef DEBUG_PRINT
    printf("Hooked sockatmark(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        // lwIP anyway doesn't implement MSG_OOB, yet
        errno = EINVAL;
        return -1;
    }
    assert(real_sockatmark != nullptr);
    return real_sockatmark(sockfd);
}

#define S_IFSOCK 0140000

int isfdtype(int fd, int fdtype) {
#ifdef DEBUG_PRINT
    printf("Hooked isfdtype(%d, %d)\n", fd, fdtype);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
        return fdtype == S_IFSOCK;
    }
    assert(real_isfdtype != nullptr);
    return real_isfdtype(fd, fdtype);
}

int dup(int oldfd) throw () {
#ifdef DEBUG_PRINT
    printf("Hooked dup(%d)\n", oldfd);
    fflush(stdout);
#endif
    // not supported for lwIP sockets
    if (unlikely(oldfd >= LWIP_SOCKET_OFFSET)) {
        errno = EBADF;  // TODO: there is no adequate error type
        return -1;
    }
    assert(real_dup != nullptr);
    return real_dup(oldfd);
}

int dup2(int oldfd, int newfd) {
#ifdef DEBUG_PRINT
    printf("Hooked dup2(%d, %d)\n", oldfd, newfd);
    fflush(stdout);
#endif
    // not supported for lwIP sockets
    if (unlikely(oldfd >= LWIP_SOCKET_OFFSET)) {
        errno = EBADF;  // TODO: there is no adequate error type
        return -1;
    }
    assert(real_dup2 != nullptr);
    auto res = real_dup2(oldfd, newfd);
    assert(newfd < LWIP_SOCKET_OFFSET || res == -1 && errno == EBADF);
    return res;
}

int dup3(int oldfd, int newfd, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked dup3(%d, %d, %d)\n", oldfd, newfd, flags);
    fflush(stdout);
#endif
    // not supported for lwIP sockets
    if (unlikely(oldfd >= LWIP_SOCKET_OFFSET)) {
        errno = EBADF;  // TODO: there is not adequate error type
        return -1;
    }
    assert(real_dup3 != nullptr);
    auto res = real_dup3(oldfd, newfd, flags);
    assert(newfd < LWIP_SOCKET_OFFSET || res == -1 && errno == EBADF);
    return res;
}
