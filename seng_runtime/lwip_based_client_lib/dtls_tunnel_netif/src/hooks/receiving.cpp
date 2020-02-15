#include "hooks/receiving.hpp"

#include "HookCommons.hpp"


void init_receiving_hooks(void *libc_handle) {
    real_recv = (ssize_t (*)(int, void *, size_t, int)) dlsym(libc_handle, "recv");
    if(unlikely(real_recv == nullptr)) throw std::runtime_error("dlsym(recv) failed");
    
    real_recvfrom = (ssize_t (*)(int, void *, size_t, int, struct sockaddr *, socklen_t *)) dlsym(libc_handle, "recvfrom");
    if(unlikely(real_recvfrom == nullptr)) throw std::runtime_error("dlsym(recvfrom) failed");
    
    real_recvmsg = (ssize_t (*)(int, struct msghdr *, int)) dlsym(libc_handle, "recvmsg");
    if(unlikely(real_recvmsg == nullptr)) throw std::runtime_error("dlsym(recvmsg) failed");
    
    real_recvmmsg = (int (*)(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *)) dlsym(libc_handle, "recvmmsg");
    if(unlikely(real_recvmmsg == nullptr)) throw std::runtime_error("dlsym(recvmmsg) failed");
    
    real_read = (ssize_t (*)(int, void *, size_t)) dlsym(libc_handle, "read");
    if(unlikely(real_read == nullptr)) throw std::runtime_error("dlsym(read) failed");
    
    real_readv = (ssize_t (*)(int, const struct iovec *, int)) dlsym(libc_handle, "readv");
    if(unlikely(real_readv == nullptr)) throw std::runtime_error("dlsym(readv) failed");
    
    /* fortified_functions */
    real__recv_chk = (ssize_t (*)(int, void *, size_t, size_t, int)) dlsym(libc_handle, "__recv_chk");
    if(unlikely(real__recv_chk == nullptr)) throw std::runtime_error("dlsym(__recv_chk) failed");
    
    real__read_chk = (ssize_t (*)(int, void *, size_t, size_t)) dlsym(libc_handle, "__read_chk");
    if(unlikely(real__read_chk == nullptr)) throw std::runtime_error("dlsym(__read_chk) failed");
}

ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked recv(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_recv(sockfd, buf, len, flags);
#ifdef DEBUG_PRINT
        auto safe = errno;
        printf("lwip_recv() returned %ld\n", ret);
        fflush(stdout);
        errno = safe;
#endif
        return ret;
    }
    assert(real_recv != nullptr);
    return real_recv(sockfd, buf, len, flags);
}

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked recvfrom()\n");
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    }
    assert(real_recvfrom != nullptr);
    return real_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked recvmsg()\n");
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_recvmsg(sockfd, msg, flags);
    }
    assert(real_recvmsg != nullptr);
    return real_recvmsg(sockfd, msg, flags);
}

int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout) {
#ifdef DEBUG_PRINT
    printf("[WARNING] Hooked recvmmsg(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        throw std::runtime_error("recvmmsg() NOT YET SUPPORTED BY LWIP\n");
    }
    assert(real_recvmmsg != nullptr);
    return real_recvmmsg(sockfd, msgvec, vlen, flags, timeout);
}

ssize_t read(int fd, void *buf, size_t count) {
#ifdef DEBUG_PRINT
    printf("Hooked read(%d, count=%lu)\n", fd, count);
    fflush(stdout);
#endif
    // if from lwIP fd range
    // netif tunnel uses read() for receive, so optimize for it
    // PROBLEM: apps also often use read/write on socket FDs! cannot optimize for both :/
    if (unlikely(fd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_read(fd, buf, count);
#ifdef DEBUG_PRINT
        auto safe = errno;
        printf("lwip_read() returns with: %ld\n", ret);
        fflush(stdout);
        errno = safe;
#endif
        return ret;
    }
    assert(real_read != nullptr);
    return real_read(fd, buf, count);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
#ifdef DEBUG_PRINT
    printf("Hooked readv(%d)\n", fd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
        return lwip_readv(fd, iov, iovcnt);
    }
    assert(real_readv != nullptr);
    return real_readv(fd, iov, iovcnt);
}

/* fortified functions */
ssize_t __recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags) {
    // buflen is the len of the obj the buf points to, known @CompileTime
#ifdef DEBUG_PRINT
    printf("Hooked __recv_chk(%d) [FORTIFIED_FUNCTION]\n", fd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
        /*
        if (n > buflen) {
            //throw std::runtime_error("recv OVERFLOW DETECTED");
             __chk_fail();
        }
         */
        return lwip_recv(fd, buf, n, flags);
    }
    assert(real__recv_chk != nullptr);
    return real__recv_chk(fd, buf, n, buflen, flags);
}

ssize_t __read_chk (int __fd, void *__buf, size_t __nbytes, size_t __buflen) {
#ifdef DEBUG_PRINT
    printf("Hooked __read_chk(%d) [FORTIFIED_FUNCTION]\n", __fd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    // netif tunnel uses read() for receive, so optimize for it
    if (unlikely(__fd >= LWIP_SOCKET_OFFSET)) {
        return lwip_read(__fd, __buf, __nbytes);
    }
    assert(real__read_chk != nullptr);
    return real__read_chk(__fd, __buf, __nbytes, __buflen);
}
