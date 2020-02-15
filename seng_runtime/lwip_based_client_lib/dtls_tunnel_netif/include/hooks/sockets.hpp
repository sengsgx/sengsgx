#ifndef SENG_HOOKS_SOCKETS_HPP
#define SENG_HOOKS_SOCKETS_HPP


#include <unistd.h> // might introduce lwip-inconsistent socklen_t definition?

/* Shadowing Socket API functions */
#ifdef __cplusplus
extern "C" {    // avoids name mangling
#endif
    int socket(int, int, int);
    
    /* Trampoline Function to "real" [libc] function */
    int seng_socket(int, int, int);
    
    int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    
    int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    
    int listen(int sockfd, int backlog);
    int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
    int accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags);
    
    int close(int fd);
    int shutdown(int sockfd, int how);

#ifdef __cplusplus
}
#endif

/* Function Pointers to "real" [libc] Socket API functions */
static int (*real_socket)(int, int, int);

static int (*real_connect)(int, const struct sockaddr *, socklen_t);

static int (*real_bind)(int, const struct sockaddr *, socklen_t);

static int (*real_listen)(int, int);
static int (*real_accept)(int, struct sockaddr *, socklen_t *);
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);

static int (*real_close)(int);
static int (*real_shutdown)(int, int);

void init_sockets_hooks(void *libc_handle);

#endif /* SENG_HOOKS_SOCKETS_HPP */
