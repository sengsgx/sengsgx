#ifndef SENG_HOOKS_RECEIVING_HPP
#define SENG_HOOKS_RECEIVING_HPP

#include <unistd.h> // ssize_t

/* Shadowing Socket API functions */
extern "C" {    // avoids name mangling
    ssize_t recv(int sockfd, void *buf, size_t len, int flags);
    ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                     struct sockaddr *src_addr, socklen_t *addrlen);
    ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
    int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout);
    
    ssize_t read(int fd, void *buf, size_t count);
    ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
    
    /* fortified functions for checking CT-known buffer size against size arg */
    ssize_t __recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags);
    ssize_t __read_chk (int __fd, void *__buf, size_t __nbytes, size_t __buflen);
}

/* Function Pointers to "real" [libc] Socket API functions */
static ssize_t (*real_recv)(int, void *, size_t, int);
static ssize_t (*real_recvfrom)(int, void *, size_t, int,
                                struct sockaddr *, socklen_t *);
static ssize_t (*real_recvmsg)(int, struct msghdr *, int);
static int (*real_recvmmsg)(int, struct mmsghdr *, unsigned int, unsigned int, struct timespec *);

static ssize_t (*real_read)(int, void *, size_t);
static ssize_t (*real_readv)(int, const struct iovec *, int);

/* fortified functions */
static ssize_t (*real__recv_chk)(int, void *, size_t, size_t, int);
static ssize_t (*real__read_chk)(int, void *, size_t, size_t);

void init_receiving_hooks(void *libc_handle);

#endif /* SENG_HOOKS_RECEIVING_HPP */
