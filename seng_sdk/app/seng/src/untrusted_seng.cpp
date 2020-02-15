#include "untrusted_seng.hpp"

#include <unistd.h> // close
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>

#include <stdio.h> // printf

#include <sys/epoll.h>
#include <cerrno>

#include "seng_u.h"

//#define DEBUG_USENG

int setup_tunnel_socket(short port, const char *dst_ip) {
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) return udp_socket;

    struct sockaddr_in target {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {0}
    };

    if (inet_aton(dst_ip, &target.sin_addr) < 0) {
        close(udp_socket);
        return -1;
    }

   if (connect(udp_socket, (struct sockaddr *)&target, sizeof(target)) < 0) {
        close(udp_socket);
        return -1;
    }

    return udp_socket;   
}

long u_direct_write(int fd, const void *buf, size_t count) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG write (%d, .., %ld)\n", fd, count);
    auto ret = write (fd, buf, count);
    auto tmp = errno;
    printf("write >> %ld\n", ret);
    errno = tmp;
    return ret;
#else
    return write (fd, buf, count);
#endif
}

long u_direct_read(int fd, void *buf, size_t count) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG read (%d, .., %ld)\n", fd, count);
#endif
    return u_direct_recv(fd, buf, count, 0);
}

int u_direct_setsockopt(int sockfd, int level, int optname, 
                        const void *optval, unsigned int optlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG setsockopt(%d, %d, %d)\n", sockfd, level, optname);
#endif
    return setsockopt(sockfd, level, optname, optval, optlen);
}

int u_hacky_direct_getsockopt(int sockfd, int level, int optname, void *optval, unsigned int optlen, unsigned int *res_optlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG getsockopt(%d, %d, %d, input optlen: %d | %d)\n", sockfd, level, optname, optlen, (res_optlen == nullptr ? -1 : *res_optlen));
#endif
    return getsockopt(sockfd, level, optname, optval, res_optlen);
}

int u_hacky_direct_getsockname(int sockfd, void *addr, unsigned int addrlen, unsigned int *res_addrlen) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG getsockname(%d, input addrlen: %d | %d)\n", sockfd, addrlen, (res_addrlen == nullptr ? -1 : *res_addrlen));
#endif
    return getsockname(sockfd, (struct sockaddr *)addr, res_addrlen);
}

long u_direct_recv(int fd, void *buf, size_t count, int flags) {
#ifdef DEBUG_USENG
    printf("[Enclave] SENG recv (%d, .., %ld, %d)\n", fd, count, flags);
    long ret = -1;
    int tmp = EINTR;
    /*while (ret < 0 && tmp == EINTR) {
        ret = recv (fd, buf, count, flags);
        tmp = errno;
    }*/
    ret = recv (fd, buf, count, flags);
    tmp = errno;
    printf("recv << %ld (%d)\n", ret, tmp);
    errno = tmp;
    return ret;
#else
    return recv (fd, buf, count, flags);
#endif
}


int seng_clock_gettime(int clk_id, struct seng_timespec *tp) {
    return clock_gettime(clk_id, (struct timespec *)tp);
}

// TODO: requires changes to BIO of recv-SSL socket, bcs. it will have to
//       read from buffers rather than calling socket recv();
int tunnel_recv_loop(int fd) {
    unsigned char *buf[2500] {};
    ssize_t plen {-1}; 
    int ret {0};

    int epollfd = epoll_create(2); // arg ignored
    struct epoll_event ev = {
        .events = EPOLLIN,
    };
    ev.data.fd = fd;
    epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &ev);
    
    int nfds;
    for (;;) {
        struct epoll_event events[1];
        nfds = epoll_wait(epollfd, events, 1, -1);

        // socket close
        if (__glibc_unlikely(nfds == 0)) break;

        // on error
        if (__glibc_unlikely(nfds == -1)) {
            if (errno == EINTR) continue;
            return -1;
        }

        // receive input
        plen = recv(fd, buf, sizeof(buf), 0);
        if (plen <= 0) continue;

        // push to netif/lwIP
        sgx_status_t status = input_tunnel_packet(global_eid, &ret, buf, plen);
        if (status != SGX_SUCCESS) {
            // TODO: switch-case with retry/break
            printf("Failed to input tunnel packet!\n");
            return -1;
        }

        if (ret < 0) break;
    }

    return 0;
}

/* OCall functions */
void uprint(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
    fflush(stdout);
}
