#include "hooks/polling.hpp"

#include "HookCommons.hpp"

#define ENABLE_MIXED_SELECT
//#define IGNORE_MIXED_SELECT


void init_polling_hooks(void *libc_handle) {
    real_poll = (int (*)(struct pollfd *, nfds_t, int)) dlsym(libc_handle, "poll");
    if(unlikely(real_poll == nullptr)) throw std::runtime_error("dlsym(poll) failed");
    
    real_select = (int (*)(int, fd_set *, fd_set *, fd_set *, struct timeval *)) dlsym(libc_handle, "select");
    if(unlikely(real_select == nullptr)) throw std::runtime_error("dlsym(select) failed");
    
    real_pselect = (int (*)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *)) dlsym(libc_handle, "pselect");
    if(unlikely(real_pselect == nullptr)) throw std::runtime_error("dlsym(pselect) failed");
    
    real_ppoll = (int (*)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *)) dlsym(libc_handle, "ppoll");
    if(unlikely(real_ppoll == nullptr)) throw std::runtime_error("dlsym(ppoll) failed");
    
    real_epoll_ctl = (int (*)(int, int, int, struct epoll_event *)) dlsym(libc_handle, "epoll_ctl");
    if(unlikely(real_epoll_ctl == nullptr)) throw std::runtime_error("dlsym(epoll_ctl) failed");
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
#ifdef DEBUG_PRINT
    printf("Hooked poll(%p, %lu, %d)\n", fds, nfds, timeout);
    fflush(stdout);
#endif
    if( unlikely(nfds==0 || !fds) ) { errno=EFAULT; return -1; }
    if( unlikely(   (nfds > (FD_SETSIZE - LWIP_SOCKET_OFFSET))
                 || (nfds > (LWIP_SOCKET_OFFSET-1)) ) ) {
        fprintf(stderr, "poll() got called with too high nfds value; would cross FD border\n");
        errno=EFAULT;
        return -1;
    }
    
#ifdef DEBUG_PRINT
    printf("1.st pollfd entry: %d, %d\n", fds->fd, fds->events);
    fflush(stdout);
#endif
    
    // currently we only support exclusive LWIP, or non-LWIP socket FDs
    if (fds[0].fd >= LWIP_SOCKET_OFFSET) {
#ifdef DEBUG_PRINT
        printf("lwip_poll() path\n");
        fflush(stdout);
#endif
        // only lwip
        for(int i=0; i<nfds; i++) {
            if ( unlikely(fds[i].fd < LWIP_SOCKET_OFFSET) ) {
                fprintf(stderr, "poll() got called with mixed FDS; we DON'T support that\n");
                errno=EFAULT;
                return -1;
            }
        }
        auto ret = lwip_poll(fds, nfds, timeout);
#ifdef DEBUG_PRINT
        auto save = errno;
        printf("lwip_poll() returned\n");
        fflush(stdout);
        errno = save; // restore
#endif
        return ret;
    }
    
#ifdef DEBUG_PRINT
    printf("system's poll() path\n");
    fflush(stdout);
#endif
    // only system
    for(int i=0; i<nfds; i++) {
        if ( unlikely(fds[i].fd >= LWIP_SOCKET_OFFSET) ) {
            fprintf(stderr, "poll() got called with mixed FDS; we DON'T support that\n");
            fflush(stderr);
            errno=EFAULT;
            return -1;
        }
    }
    assert(real_poll != nullptr);
    return real_poll(fds, nfds, timeout);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
#ifdef DEBUG_PRINT
    printf("Hooked select(%d, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout);
    fflush(stdout);
#endif
    if( unlikely(nfds < 0) ) { errno=EINVAL; return -1; }
    
    if( nfds-1 >= LWIP_SOCKET_OFFSET ) {
        fd_set sys_readfds, sys_writefds, sys_exceptfds;
        bool sys_fds {false};
        int last_sys_fd {-2};
        FD_ZERO(&sys_readfds);
        FD_ZERO(&sys_writefds);
        FD_ZERO(&sys_exceptfds);
        // Check which system FDs have been set by the caller
        for(int i=0; i<LWIP_SOCKET_OFFSET; i++) {
            if (readfds != nullptr && FD_ISSET(i, readfds)) {
#ifdef DEBUG_PRINT
                printf("%d is set for read-listen\n", i);
#endif
                FD_SET(i, &sys_readfds);
                last_sys_fd = i;
            }
            if (writefds != nullptr && FD_ISSET(i, writefds)) {
#ifdef DEBUG_PRINT
                printf("%d is set for write-listen\n", i);
#endif
                FD_SET(i, &sys_writefds);
                last_sys_fd = i;
            }
            if (exceptfds != nullptr && FD_ISSET(i, exceptfds)) {
#ifdef DEBUG_PRINT
                printf("%d is set for except-listen\n", i);
#endif
                FD_SET(i, &sys_exceptfds);
                last_sys_fd = i;
            }
        }
        // Found at least one System FD
        if (last_sys_fd >= 0) sys_fds = true;
#ifdef DEBUG_PRINT
        // Print lwIP Sockets that have been chosen for select()
        for(int i=LWIP_SOCKET_OFFSET; i<=nfds-1; i++) {
            if (readfds != nullptr && FD_ISSET(i, readfds)) printf("%d is set for read-listen\n", i);
            if (writefds != nullptr && FD_ISSET(i, writefds)) printf("%d is set for write-listen\n", i);
            if (exceptfds != nullptr && FD_ISSET(i, exceptfds)) printf("%d is set for except-listen\n", i);
        }
        fflush(stdout);
#endif
        int ret;
        if (!sys_fds) {
#ifdef DEBUG_PRINT
            printf("only sockets to be selected on\n");
            fflush(stdout);
#endif
            // only sockets, done
            ret = lwip_select(nfds, readfds, writefds, exceptfds, timeout);
        } else {
#ifndef ENABLE_MIXED_SELECT
            
#ifdef IGNORE_MIXED_SELECT
            // call anyway
            ret = lwip_select(nfds, readfds, writefds, exceptfds, timeout);
#else
            errno = EBADF;
            ret = -1;
#endif // IGNORE_MIXED_SELECT
            
#else
#ifdef DEBUG_PRINT
            printf("mixing sockets and system FDs in select sets\n");
            fflush(stdout);
#endif
            // mixed sockets and system, that's a big issue; should actually patch it inside lwIP to make it (more) efficient!
            bool timeout_specified {false};
            bool one_round_no_wait {false};
            struct timeval remaining_timeout {0,0};
            struct timeval wait_some_time {0,250000}; // 250,000 micro-sec = 250 ms = 1/4 sec
            struct timeval just_check {0,0}; // check, then immediately return
            // get specified timeout
            if (timeout != nullptr) {
                remaining_timeout.tv_sec = timeout->tv_sec;
                remaining_timeout.tv_usec = timeout->tv_usec;
                timeout_specified = true;
                // if specified timeout smaller than step-size, wait specified time
                if (1e6 * remaining_timeout.tv_sec + remaining_timeout.tv_usec
                    < 1e6 * wait_some_time.tv_sec + wait_some_time.tv_usec) {
                    wait_some_time.tv_sec = remaining_timeout.tv_sec;
                    wait_some_time.tv_usec = remaining_timeout.tv_usec;
                }
                if (timeout->tv_sec == 0 && timeout->tv_usec == 0) {
                    one_round_no_wait = true;
                }
            }
            
#ifdef DEBUG_PRINT
            if (timeout_specified) {
                printf("timeout specified\n");
            } else {
                printf("no timeout specified, will loop forever\n");
            }
            printf("Remaining time: %ld sec, %ld microsec\n", remaining_timeout.tv_sec, remaining_timeout.tv_usec);
            fflush(stdout);
#endif
            
            // if no timeout specified by caller: wait until event or error occurs
            // else, will stepwise reduce timeout until 0
            // EXCEPTION: if timeout 0 was explicitly specified, it should be exactly 1 round
            while (!timeout_specified ||
                   (remaining_timeout.tv_sec > 0 || remaining_timeout.tv_usec > 0) ||
                   one_round_no_wait) {
                
                // need to create backup, bcs. timeout seems to ZERO out all sets
                fd_set read_cpy, write_cpy, except_cpy, sys_read_cpy, sys_write_cpy, sys_except_cpy;
                if (readfds != nullptr) {
                    memcpy(&read_cpy, readfds, sizeof(fd_set));
                    memcpy(&sys_read_cpy, readfds, sizeof(fd_set));
                }
                if (writefds != nullptr) {
                    memcpy(&write_cpy, writefds, sizeof(fd_set));
                    memcpy(&sys_write_cpy, writefds, sizeof(fd_set));
                }
                if (exceptfds != nullptr) {
                    memcpy(&except_cpy, exceptfds, sizeof(fd_set));
                    memcpy(&sys_except_cpy, exceptfds, sizeof(fd_set));
                }
                
                ret = lwip_select(nfds,
                                  (readfds == nullptr ? nullptr : &read_cpy),
                                  (writefds == nullptr ? nullptr : &write_cpy),
                                  (exceptfds == nullptr ? nullptr : &except_cpy),
                                  &wait_some_time);
                auto safe = errno;
                
                // if explicit 0 timeout, set false, s.t. we will stop loop after processing the results
                one_round_no_wait = false;
                
#ifdef DEBUG_PRINT
                printf("intermediate lwip_select returned %d\n", ret);
                fflush(stdout);
#endif
                
                // Error
                if (ret < 0) {
                    errno = safe;
                    break;
                }
                
                // Check system events
                assert(real_select != nullptr);
                int sys_ret = real_select(last_sys_fd+1,
                                          (readfds == nullptr ? nullptr : &sys_read_cpy),
                                          (writefds == nullptr ? nullptr : &sys_write_cpy),
                                          (exceptfds == nullptr ? nullptr : &sys_except_cpy),
                                          &just_check);
                safe = errno;
                
#ifdef DEBUG_PRINT
                printf("intermediate real_select returned %d\n", sys_ret);
                fflush(stdout);
#endif
                
                assert(ret >= 0);
                
                // Error on system side, no events on socket side
                if (sys_ret < 0 && ret == 0) {
                    // set error return value
                    ret = sys_ret;
                    // restore errno
                    errno = safe;
                    break;
                }
                
                assert(sys_ret >= 0 || ret > 0);
                
                // Both no events
                if (ret == 0 && sys_ret == 0) {
                    // No timeout specified, i.e. we anyway loop forever
                    if (!timeout_specified) {
#ifdef DEBUG_PRINT
                        printf("No Events. Continue waiting\n");
                        fflush(stdout);
#endif
                        continue;
                    }
                    
                    // Timeout specified, so decrease remaining time
                    long t_old = remaining_timeout.tv_sec * 1e6 + remaining_timeout.tv_usec;
#ifdef DEBUG_PRINT
                    printf("Both time'd out, old remaining time: %ld\n", t_old);
                    fflush(stdout);
#endif
                    t_old -= wait_some_time.tv_sec * 1e6 + wait_some_time.tv_usec;
#ifdef DEBUG_PRINT
                    printf("New remaining time: %ld\n", t_old);
                    fflush(stdout);
#endif
                    // abort while loop
                    if (t_old <= 0) {
                        remaining_timeout.tv_sec = 0;
                        remaining_timeout.tv_usec = 0;
                        
                        // timeout, clear fd_sets
                        if(readfds != nullptr) FD_ZERO(readfds);
                        if(writefds != nullptr) FD_ZERO(writefds);
                        if(exceptfds != nullptr) FD_ZERO(exceptfds);
#ifdef DEBUG_PRINT
                        printf("timeout reached, should now return from select\n");
                        fflush(stderr);
#endif
                    } else {
                        remaining_timeout.tv_sec = t_old / 1e6;
                        remaining_timeout.tv_usec = t_old % (unsigned long)1e6;
                    }
                    continue;
                }
                
                // At least some events
                assert(sys_ret > 0 || ret > 0);
                
                // Clear for output
                if(readfds != nullptr) FD_ZERO(readfds);
                if(writefds != nullptr) FD_ZERO(writefds);
                if(exceptfds != nullptr) FD_ZERO(exceptfds);
                
                // Copy Socket Events
                if (ret > 0) {
                    if(readfds != nullptr) memcpy(readfds, &read_cpy, sizeof(fd_set));
                    if(writefds != nullptr) memcpy(writefds, &write_cpy, sizeof(fd_set));
                    if(exceptfds != nullptr) memcpy(exceptfds, &except_cpy, sizeof(fd_set));
                }
                
                // Add System Events
                if (sys_ret > 0) {
                    for (int i=0; i<LWIP_SOCKET_OFFSET; i++) {
                        if(readfds != nullptr && FD_ISSET(i, &sys_read_cpy)) FD_SET(i, readfds);
                        if(writefds != nullptr && FD_ISSET(i, &sys_write_cpy)) FD_SET(i, writefds);
                        if(exceptfds != nullptr && FD_ISSET(i, &sys_except_cpy)) FD_SET(i, exceptfds);
                    }
                    // add #events
                    assert(ret >= 0);
                    ret += sys_ret;
                }
                
                // output is ready; we have at least 1 type of events
                break;
            } // while end
#endif // ENABLE_MIXED_SELECT
            
        } // else end
#ifdef DEBUG_PRINT
        auto safe = errno;
        printf("lwip_select returned with %d\n", ret);
        fflush(stdout);
        errno = safe;
#endif
        return ret;
    }
 
    assert(real_select != nullptr);
    return real_select(nfds, readfds, writefds, exceptfds, timeout);
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
#ifdef DEBUG_PRINT
    printf("Hooked pselect(%d, %p, %p, %p, %p, %p)\n", nfds, readfds, writefds, exceptfds, timeout, sigmask);
    fflush(stdout);
#endif
    if( unlikely(nfds < 0) ) { errno=EINVAL; return -1; }
    
    // TODO: actually have to check that no FDs from both FD no. ranges are used at the same time
    
    if( nfds-1 >= LWIP_SOCKET_OFFSET ) {
        throw std::runtime_error("pselect() NOT YET SUPPORTED FOR LWIP\n");
    }
    
    assert(real_pselect != nullptr);
    return real_pselect(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask) {
#ifdef DEBUG_PRINT
    printf("Hooked ppoll(%p, %lu, %p, %p)\n", fds, nfds, tmo_p, sigmask);
    fflush(stdout);
#endif
    if( unlikely(nfds==0 || !fds) ) { errno=EFAULT; return -1; }
    if( unlikely(   (nfds > (FD_SETSIZE - LWIP_SOCKET_OFFSET))
                 || (nfds > (LWIP_SOCKET_OFFSET-1)) ) ) {
        fprintf(stderr, "ppoll() got called with too high nfds value; would cross FD border\n");
        errno=EFAULT;
        return -1;
    }
    
#ifdef DEBUG_PRINT
    printf("1.st ppollfd entry: %d, %d\n", fds->fd, fds->events);
    fflush(stdout);
#endif
    
    // currently we only support exclusive LWIP, or non-LWIP socket FDs
    if (fds[0].fd >= LWIP_SOCKET_OFFSET) {
        throw std::runtime_error("ppoll() NOT YET SUPPORTED FOR LWIP\n");
    }
    
#ifdef DEBUG_PRINT
    printf("system's ppoll() path\n");
    fflush(stdout);
#endif
    // only system
    for(int i=0; i<nfds; i++) {
        if ( unlikely(fds[i].fd >= LWIP_SOCKET_OFFSET) ) {
            fprintf(stderr, "ppoll() got called with mixed FDS; we DON'T support that\n");
            fflush(stderr);
            errno=EFAULT;
            return -1;
        }
    }
    assert(real_ppoll != nullptr);
    return real_ppoll(fds, nfds, tmo_p, sigmask);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
#ifdef DEBUG_PRINT
    printf("Hooked epoll_ctl(%d, %d, %d, %p)\n", epfd, op, fd, event);
    fflush(stdout);
#endif

    if( unlikely(fd >= LWIP_SOCKET_OFFSET) ) {
        throw std::runtime_error("epoll_ctrl() NOT YET SUPPORTED FOR LWIP\n");
    }
    
    assert(real_epoll_ctl != nullptr);
    return real_epoll_ctl(epfd, op, fd, event);
}
