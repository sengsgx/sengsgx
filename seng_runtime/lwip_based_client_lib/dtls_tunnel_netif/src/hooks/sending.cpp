#include "hooks/sending.hpp"

#include "HookCommons.hpp"


void init_sending_hooks(void *libc_handle) {
    real_send = (ssize_t (*)(int, const void *, size_t, int)) dlsym(libc_handle, "send");
    if(unlikely(real_send == nullptr)) throw std::runtime_error("dlsym(send) failed");
    
    real_sendto = (ssize_t (*)(int, const void *, size_t, int, const struct sockaddr *, socklen_t)) dlsym(libc_handle, "sendto");
    if(unlikely(real_sendto == nullptr)) throw std::runtime_error("dlsym(sendto) failed");
    
    real_sendmsg = (ssize_t (*)(int sockfd, const struct msghdr *msg, int flags)) dlsym(libc_handle, "sendmsg");
    if(unlikely(real_sendmsg == nullptr)) throw std::runtime_error("dlsym(sendmsg) failed");
    
    real_sendmmsg = (int (*)(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                             unsigned int flags)) dlsym(libc_handle, "sendmmsg");
    //if(unlikely(real_sendmmsg != nullptr)) throw std::runtime_error("dlsym(sendmmsg) should NOT(!) SUCCEED");
    
    real_write = (ssize_t (*)(int, const void *, size_t)) dlsym(libc_handle, "write");
    if(unlikely(real_write == nullptr)) throw std::runtime_error("dlsym(write) failed");
    
    real_writev = (ssize_t (*)(int, const struct iovec *, int)) dlsym(libc_handle, "writev");
    if(unlikely(real_writev == nullptr)) throw std::runtime_error("dlsym(writev) failed");
    
    real_sendfile = (ssize_t (*)(int, int, off_t *, size_t)) dlsym(libc_handle, "sendfile");
    if(unlikely(real_sendfile == nullptr)) throw std::runtime_error("dlsym(sendfile) failed");
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked send()\n");
    fflush(stdout);
#endif
    // if from lwIP fd range
    // netif tunnel uses write() for sending, so optimize for it
    if (unlikely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_send(sockfd, buf, len, flags);
    }
    assert(real_send != nullptr);
    return real_send(sockfd, buf, len, flags);
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
#ifdef DEBUG_PRINT
    printf("Hooked sendto()\n");
    printf("sendto(%d, ..., %p, %d)\n", sockfd, dest_addr, addrlen);
    printf("AF_INET: %d\n", AF_INET);
    printf("->sa_family: %d\n", dest_addr->sa_family);
    printf("sizeof(struct sockaddr): %lu\n", sizeof(struct sockaddr));
    printf("sizeof(struct sockaddr_in): %lu\n", sizeof(struct sockaddr_in));
    //printf("Offset len: %lu\n", offsetof(struct sockaddr, sa_len));
    printf("Offset family: %lu\n", offsetof(struct sockaddr, sa_family));
    
    for (int i=0; i<sizeof(struct sockaddr); i++)
        printf("%hhx, ", ((const unsigned char *) dest_addr)[i]);
    printf("\n");
    
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
    }
    assert(real_sendto != nullptr);
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) {
#ifdef DEBUG_PRINT
    printf("Hooked sendmsg()\n");
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        return lwip_sendmsg(sockfd, msg, flags);
    }
    assert(real_sendmsg != nullptr);
    return real_sendmsg(sockfd, msg, flags);
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
             unsigned int flags) {
#ifdef DEBUG_PRINT
    printf("[WARNING] Hooked sendmmsg(%d)\n", sockfd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(sockfd >= LWIP_SOCKET_OFFSET)) {
        throw std::runtime_error("recvmmsg() NOT YET SUPPORTED BY LWIP\n");
    }
    assert(real_sendmmsg != nullptr);
    return real_sendmmsg(sockfd, msgvec, vlen, flags);
}

ssize_t write(int fd, const void *buf, size_t count) {
#ifdef DEBUG_PRINT
    printf("Hooked write(%d, %p, %lu)\n", fd, buf, count);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_write(fd, buf, count);
#ifdef DEBUG_PRINT
        auto safe = errno;
        printf("lwip_write() returned %ld\n", ret);
        errno = safe;
#endif
        return ret;
    }
    assert(real_write != nullptr);
    return real_write(fd, buf, count);
}


// observed in resolv/res_send.c
ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
#ifdef DEBUG_PRINT
    printf("Hooked writev(%d)\n", fd);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(fd >= LWIP_SOCKET_OFFSET)) {
        auto ret = lwip_writev(fd, iov, iovcnt);
#ifdef DEBUG_PRINT
        auto safe = errno;
        printf("lwip_writev() returned %ld\n", ret);
        errno = safe;
#endif
        return ret;
    }
    assert(real_writev != nullptr);
    return real_writev(fd, iov, iovcnt);
}


ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
#ifdef DEBUG_PRINT
    printf("Hooked sendfile(out: %d, in: %d, count: %lu) [no lwIP support]\n", out_fd, in_fd, count);
    fflush(stdout);
#endif
    // if from lwIP fd range
    if (likely(out_fd >= LWIP_SOCKET_OFFSET)) {
        // no sendfile() support in lwIP
        errno = EINVAL;
        return -1;
    }
    assert(real_sendfile != nullptr);
    return real_sendfile(out_fd, in_fd, offset, count);
}
