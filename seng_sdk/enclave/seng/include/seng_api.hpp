#ifndef SENG_T_API_H
#define SENG_T_API_H

#if defined(__cplusplus)
extern "C" {
#endif

int init_seng_runtime(const char *server_ip, short server_port);
/* TODO: add shutdown_seng_runtime();
 * which terminates lwIP and tunnel thread, s.t. sgx_destroy_enclave() does not hang anymore
 */

/* --------------------------------- */

//#ifndef __socklen_t_defined
//typedef unsigned int socklen_t;
//#define __socklen_t_defined
//#endif

#include <unistd.h> // might introduce lwip-inconsistent socklen_t definition?
//#include <cstdarg>  // va_list
#include <stdarg.h> // va_list
#include <lwip/sockets.h>   // good idea? (socklen_t, nfds_t, fd_set)
#include <lwip/netdb.h>     // for "struct addrinfo"

// TODO: other lwip headers for constants/types?

#define unsupported_SOCK_CLOEXEC (02000000)
// for accept4() emulation (TODO: can consider dropping accept4)
#ifndef SOCK_NONBLOCK
    #define SOCK_NONBLOCK O_NONBLOCK
#endif

/* Shadowing getinfo API */
int seng_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int seng_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

/* TODO: While the DNS Server is set by the SENG initialization and securely
 * contacted through the tunnel, the SENG-SDK prototype does NOT YET provide
 * hard-coded/integrity-protected versions for configuration files like /etc/resolv.conf
 * or /etc/services which are used by 3rd party libraries.
 * A future version can introduce a measured manifest file with secure file
 * hashes of configuration files, and an API for integrity-protected file access
 * (-> lightweight file-system shield) */
int seng_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res);
void seng_freeaddrinfo(struct addrinfo *res);

struct hostent *seng_gethostbyname(const char *name);

int seng_poll(struct pollfd *fds, nfds_t nfds, int timeout);
int seng_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);

ssize_t seng_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t seng_recvfrom(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen);
ssize_t seng_recvmsg(int sockfd, struct msghdr *msg, int flags);

ssize_t seng_read(int fd, void *buf, size_t count);
ssize_t seng_readv(int fd, const struct iovec *iov, int iovcnt);

/* fortified functions for checking CT-known buffer size against size arg */
ssize_t __seng_recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags);
ssize_t __seng_read_chk (int __fd, void *__buf, size_t __nbytes, size_t __buflen);

ssize_t seng_send(int sockfd, const void *buf, size_t len, int flags);
ssize_t seng_sendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen);
ssize_t seng_sendmsg(int sockfd, const struct msghdr *msg, int flags);

ssize_t seng_write(int fd, const void *buf, size_t count);
// observed in resolv/res_send.c
ssize_t seng_writev(int fd, const struct iovec *iov, int iovcnt);

int seng_ioctl(int fd, unsigned long request, va_list args);
int seng_fcntl(int fd, int cmd, ...);

int seng_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
int seng_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);

int seng_isfdtype(int fd, int fdtype);

int seng_socket(int domain, int type, int protocol);

int seng_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int seng_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int seng_listen(int sockfd, int backlog);
int seng_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int seng_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);

int seng_close(int fd);
int seng_shutdown(int sockfd, int how);

// Not supported in lwIP at the moment
//int seng_ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
//int seng_pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
//int seng_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

//int seng_recvmmsgs(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags, struct timespec *timeout);
//int seng_sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, unsigned int flags);

//ssize_t seng_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

//int seng_dup(int oldfd) throw();
//int seng_dup2(int oldfd, int newfd);
//int seng_dup3(int oldfd, int newfd, int flags);  // Linux-specific

//int seng_sockatmark(int sockfd);


#if defined(__cplusplus)
}
#endif

#endif /* !SENG_T_API_H */
