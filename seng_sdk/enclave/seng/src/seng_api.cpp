#include "seng_api.hpp"
#include "seng_utils.h"

#include "tSgxSSL_api.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "DT_SSLEngineClient_OpenSSL.hpp"
#include "seng_tunnelmodule.hpp"

#include "seng_tunnelmodule.hpp"

extern "C" {
	#include <lwip/tcpip.h>
	#include <lwip/dns.h>
}

#include <stdexcept>

//#define SENGAPI_DEBUG

static void init_and_add_tunnel_module(void *arg) {
#ifdef SENGAPI_DEBUG
	printf("lwIP tcpip_init seems to have finished\n");
#endif

	auto init_sem = (sys_sem_t *)arg;
	seng::TunnelNetif &tn = seng::TunnelNetif::getInstance();

#ifdef SENGAPI_DEBUG
	printf("calling netif_add\n");
#endif
	auto ret_tun = netif_add(&tn.tunnel_mod, NULL, NULL, NULL, NULL, 
		seng::TunnelNetif::netif_init_trmpln, tcpip_input);
#ifdef SENGAPI_DEBUG
	printf("returned from netif_add\n");
#endif
	// TODO: this throw causes illegal HW error (I guess bcs. uncatched?)
	if (ret_tun == nullptr) throw std::runtime_error("netif_add failed\n");

	netif_set_default(&tn.tunnel_mod);
	netif_set_up(netif_default);    // starting from now on, lwIP stack will accept input IP packets from netif/link


	ip_addr_t name_server {};
	IP_ADDR4(&name_server, 127, 0, 0, 1);
	dns_setserver(0, &name_server);

	// wakeup main thread
	sys_sem_signal(init_sem);
#ifdef SENGAPI_DEBUG
	printf("finished netif setup\n");
#endif
}

int init_seng_runtime(const char *server_ip, short server_port) {
	SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);
	SGXSSLSetUnreachableCodePolicy(UNREACH_CODE_REPORT_ERR_AND_CONTNUE);
	try {
		// TODO: error case for constructor (e.g., failed attestation)
		// TODO: store somewhere else / singleton
		seng::TunnelNetif & tunnel_runtime = seng::TunnelNetif::getInstance();

		// TODO: move inside netif-init process instead?
		// [but then tcpip thread will already run even if error; though could crash it via exception...]
		// TODO: cleanup TunnelNetif object on error
		if (!tunnel_runtime.establish_dtls_tunneling(server_ip, server_port)) return -1;
	} catch(std::exception &e) {
		printf("Error: %s\n", e.what());
		return -1;
	}
	
	sys_sem_t init_sem;
	sys_sem_new(&init_sem, 0);

	// TODO: error detection/handling here!
	tcpip_init(init_and_add_tunnel_module, &init_sem);

	// wait for init of lwip thread to finish
	sys_sem_wait(&init_sem);
	sys_sem_free(&init_sem);
#ifdef SENGAPI_DEBUG
	printf("SENG init done\n");
#endif
	return 0;
}




/* SOCKET STUFF */

int seng_getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	return lwip_getsockname(sockfd, addr, addrlen);
}
int seng_getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	return lwip_getpeername(sockfd, addr, addrlen);
}

int seng_getaddrinfo(const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **res) {
	return lwip_getaddrinfo(node, service, hints, res);
}
void seng_freeaddrinfo(struct addrinfo *res) {
	lwip_freeaddrinfo(res);
}

int seng_poll(struct pollfd *fds, nfds_t nfds, int timeout) {
#ifdef SENGAPI_DEBUG
	printf("seng_poll(%p, %d, %d)\n", fds, nfds, timeout);
#endif
	return lwip_poll(fds, nfds, timeout);
}
int seng_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
	return lwip_select(nfds, readfds, writefds, exceptfds, timeout);
}

ssize_t seng_recv(int sockfd, void *buf, size_t len, int flags) {
	return lwip_recv(sockfd, buf, len, flags);
}
ssize_t seng_recvfrom(int sockfd, void *buf, size_t len, int flags,
                struct sockaddr *src_addr, socklen_t *addrlen) {
	return lwip_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
}
ssize_t seng_recvmsg(int sockfd, struct msghdr *msg, int flags) {
	return lwip_recvmsg(sockfd, msg, flags);
}

ssize_t seng_read(int fd, void *buf, size_t count) {
	return lwip_read(fd, buf, count);
}
ssize_t seng_readv(int fd, const struct iovec *iov, int iovcnt) {
	return lwip_readv(fd, iov, iovcnt);
}

/* fortified functions for checking CT-known buffer size against size arg */
ssize_t __seng_recv_chk (int fd, void *buf, size_t n, size_t buflen, int flags) {
	// TODO
	/*
	if (n > buflen) {
		throw std::runtime_error("recv OVERFLOW DETECTED");
		__chk_fail();
	}
	*/
	return lwip_recv(fd, buf, n, flags);
}
ssize_t __seng_read_chk (int __fd, void *__buf, size_t __nbytes, size_t __buflen) {
	// TODO: check
	return lwip_read(__fd, __buf, __nbytes);
}

ssize_t seng_send(int sockfd, const void *buf, size_t len, int flags) {
	return lwip_send(sockfd, buf, len, flags);
}
ssize_t seng_sendto(int sockfd, const void *buf, size_t len, int flags,
                const struct sockaddr *dest_addr, socklen_t addrlen) {
	return lwip_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
ssize_t seng_sendmsg(int sockfd, const struct msghdr *msg, int flags) {
	return lwip_sendmsg(sockfd, msg, flags);
}

ssize_t seng_write(int fd, const void *buf, size_t count) {
	return lwip_write(fd, buf, count);
}
// observed in resolv/res_send.c
ssize_t seng_writev(int fd, const struct iovec *iov, int iovcnt) {
	return lwip_writev(fd, iov, iovcnt);
}

int seng_ioctl(int fd, unsigned long request, va_list args) {
	return lwip_ioctl(fd, request, args);
}
int seng_fcntl(int fd, int cmd, ...) {
    va_list args;
    va_start(args, cmd);

	int ret;
	switch(cmd) {
		case F_SETFL:
		{
			int flags = va_arg(args, int);  // works

			// lwIP only supports O_NONBLOCK for F_SETFL; it auto-strips access-related flags
			ret = lwip_fcntl(fd, F_SETFL, flags);
			break;
		}
		case F_GETFL:
			ret = lwip_fcntl(fd, F_GETFL, 0);
			break;
		default:
			errno = EINVAL;
			return -1;
	}
	auto safe = errno;
	va_end(args);
	errno = safe;
	return ret;
}




















int seng_getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen) {
	return lwip_getsockopt(sockfd, level, optname, optval, optlen);
}
int seng_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	return lwip_setsockopt(sockfd, level, optname, optval, optlen);
}

#define S_IFSOCK 0140000

int seng_isfdtype(int fd, int fdtype) {
	return fdtype == S_IFSOCK;
}


int seng_socket(int domain, int type, int protocol) {
	/*
	* Linux allows to OR SOCK_NONBLOCK (O_NONBLOCK) and SOCK_CLOEXEC (O_CLOEXEC) to type;
	* lwIP does NOT allow that, BUT at least lwIP can support O_NONBLOCK via usual lwip_fcntl();
	* so strip O_CLOEXEC with warning, and perform O_NONBLOCK mode setting manually
	*/
	int sockfd = lwip_socket(domain,
		type,
		protocol);
	auto safe = errno;

	if(unlikely(sockfd < LWIP_SOCKET_OFFSET && sockfd != -1)) throw std::runtime_error("lwip_socket() returned FD from wrong range");

	 // set nonblock manually if requested
	/*
    if(unlikely (type & O_NONBLOCK) != 0 ) {
		printf("Setting socket non-blocking mode\n");
        // TODO: should we close on failure?
        int ret = lwip_fcntl(sockfd, F_SETFL, O_NONBLOCK);
        assert( ret == 0 );
    }
	*/

	errno = safe;
	return sockfd;
}

int seng_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	return lwip_connect(sockfd, addr, addrlen);
}

int seng_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	return lwip_bind(sockfd, addr, addrlen);
}

int seng_listen(int sockfd, int backlog) {
// TODO: listen shadowing mechanism
	return lwip_listen(sockfd, backlog);
}
int seng_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	return lwip_accept(sockfd, addr, addrlen);
}
int seng_accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags) {
	int ret = lwip_accept(sockfd, addr, addrlen);
	auto safe = errno;

	// set nonblock manually if requested
	if(unlikely ((flags & O_NONBLOCK) != 0 && ret >= 0) ) {
		// TODO: what to do on failure?
		int tmp = lwip_fcntl(ret, F_SETFL, O_NONBLOCK);
		assert( tmp == 0 );
	}
	errno = safe;
	return ret;
}

int seng_close(int fd) {
	return lwip_close(fd);
}
int seng_shutdown(int sockfd, int how) {
	return lwip_shutdown(sockfd, how);
}

struct hostent *seng_gethostbyname(const char *name) {
	return lwip_gethostbyname(name);
}
