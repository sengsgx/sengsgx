#ifndef SENG_HOOKS_SOCKCTRL_HPP
#define SENG_HOOKS_SOCKCTRL_HPP

#include <cstdarg>  // va_list
#include <unistd.h> // socklen_t

/* Shadowing Socket API functions */
extern "C" {    // avoids name mangling
    int ioctl(int fd, unsigned long request, va_list args);
    int fcntl(int fd, int cmd, ...);
    
    int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
    int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
    
    int sockatmark(int sockfd);
    
    int isfdtype(int fd, int fdtype);
    
    int dup(int oldfd) throw();
    int dup2(int oldfd, int newfd);
    int dup3(int oldfd, int newfd, int flags);  // Linux-specific
}

/* Function Pointers to "real" [libc] Socket API functions */
static int (*real_ioctl)(int, unsigned long, va_list);
static int (*real_fcntl)(int, int, ...);

static int (*real_getsockopt)(int, int, int, void *, socklen_t *);
static int (*real_setsockopt)(int, int, int, const void *, socklen_t);

static int (*real_sockatmark)(int);

static int (*real_isfdtype)(int, int);

static int (*real_dup)(int);
static int (*real_dup2)(int, int);
static int (*real_dup3)(int, int, int);

void init_sockctrl_hooks(void *libc_handle);

#endif /* SENG_HOOKS_SOCKCTRL_HPP */
