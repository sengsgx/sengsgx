#ifndef SENG_HOOKS_SENDING_HPP
#define SENG_HOOKS_SENDING_HPP

#include <unistd.h> // ssize_t

/* Shadowing Socket API functions */
extern "C" {    // avoids name mangling
    ssize_t send(int sockfd, const void *buf, size_t len, int flags);
    ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
                   const struct sockaddr *dest_addr, socklen_t addrlen);
    ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);
    int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                 unsigned int flags);
    
    ssize_t write(int fd, const void *buf, size_t count);
    // observed in resolv/res_send.c
    ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
    
    ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
}

/* Function Pointers to "real" [libc] Socket API functions */
static ssize_t (*real_send)(int, const void *, size_t, int);
static ssize_t (*real_sendto)(int, const void *, size_t, int,
                              const struct sockaddr *, socklen_t);
static ssize_t (*real_sendmsg)(int, const struct msghdr *, int);
// lwIP does NOT support it
static int (*real_sendmmsg)(int, struct mmsghdr *, unsigned int, unsigned int);

static ssize_t (*real_write)(int, const void *, size_t);
static ssize_t (*real_writev)(int, const struct iovec *, int);

static ssize_t (*real_sendfile)(int, int, off_t *, size_t);

void init_sending_hooks(void *libc_handle);

#endif /* SENG_HOOKS_SENDING_HPP */
