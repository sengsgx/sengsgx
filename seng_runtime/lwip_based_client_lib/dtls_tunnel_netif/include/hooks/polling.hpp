#ifndef SENG_HOOKS_POLLING_HPP
#define SENG_HOOKS_POLLING_HPP

#include <lwip/sockets.h>   // good idea?


/* Shadowing Socket API functions */
extern "C" {    // avoids name mangling
    int poll(struct pollfd *fds, nfds_t nfds, int timeout);
    
    int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
 
    int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask);
    
    int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);
    
    int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
}

/* Function Pointers to "real" [libc] Socket API functions */
static int (*real_poll)(struct pollfd *, nfds_t, int);

static int (*real_select)(int nfds, fd_set *, fd_set *, fd_set *, struct timeval *);

static int (*real_ppoll)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *);

static int (*real_pselect)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *);

static int (*real_epoll_ctl)(int, int, int, struct epoll_event *);

void init_polling_hooks(void *libc_handle);

#endif /* SENG_HOOKS_POLLING_HPP */
