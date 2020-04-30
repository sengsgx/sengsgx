#include <stdio.h>

#include "app_enclave.h"
#include "app_enclave_t.h"

#include <sgx_spinlock.h>
#include <sgx_thread.h>

#define ETIMEDOUT 110

#include <stdexcept>

#include "seng_api.hpp"
#include "seng_utils.h" // printf is currently here


void t_sgxssl_call_apis(int dst_ipv4)
{
    int ret = 0;
    printf("[Enclave] Start tests\n");

	printf("[Enclave] Try calling the OCALL marked as potential \"switchless\"\n");
	switchless_demo(4711);

	printf("[Enclave] Trying to init SENG runtime\n");

	// TODO: SENG Server address hardcoded to 127.0.0.1:12345/udp at the moment
	if (init_seng_runtime("127.0.0.1", 12345) < 0) {
		printf("[Enclave] Failed to init SENG runtime!\n");
	} else {
		printf("[Enclave] Success! Starting network demo.\n");

		// try seng_socket() via lwIP
		printf("[Enclave] Test creation of secure sockets\n");
		int s_udp_fd = seng_socket(PF_INET,SOCK_DGRAM,0);
		int s_udp_fd2 = seng_socket(PF_INET,SOCK_DGRAM,0);
		int s_tcp_fd = seng_socket(PF_INET,SOCK_STREAM,0);
		printf("[Enclave] s_udp_fd = %d\n", s_udp_fd);
		printf("[Enclave] s_udp_fd2 = %d\n", s_udp_fd2);
		printf("[Enclave] s_tcp_fd = %d\n", s_tcp_fd);

		printf("[Enclave] Try closing secure sockets\n");
		printf("[Enclave] close: %d\n", seng_close(s_udp_fd));
		printf("[Enclave] close: %d\n", seng_close(s_udp_fd2));
		printf("[Enclave] close: %d\n", seng_close(s_tcp_fd));

		short demo_port {8391};
		in_addr_t dst_addr = dst_ipv4;
		printf("[Enclave] Trying to connect to demo target on %s:%d/tcp!\n", inet_ntoa(dst_addr), demo_port);

		int udp_con = seng_socket(PF_INET,SOCK_STREAM,0);
		if (udp_con < 0) {
			printf("[Enclave] Faild to create socket\n");
		} else {
			struct sockaddr_in trgt;
			trgt.sin_family = AF_INET;
			trgt.sin_port = lwip_htons(demo_port);
			trgt.sin_addr.s_addr = dst_addr;
			if (-1 == seng_connect(udp_con, (const sockaddr *)&trgt, sizeof(trgt))) {
				printf("[Enclave] Connect failed\n");
			} else {
				const char *buf = "Hello from SDK-SENG!\n";
				printf("[Enclave] payload size: %d\n", strlen(buf));
				printf("[Enclave] Trying to send demo message 5 times\n");
				int ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
				printf("[Enclave] seng_send: %d\n", ret);
				ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
				printf("[Enclave] seng_send: %d\n", ret);
				ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
				printf("[Enclave] seng_send: %d\n", ret);
				ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
				printf("[Enclave] seng_send: %d\n", ret);
				ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
				printf("[Enclave] seng_send: %d\n", ret);

				char buf2[1510] {};
				buf2[1509] = '\0';

				// try lwIP timeout
				struct timeval to {
					.tv_sec = 4,
					.tv_usec = 0,
				};
				if ( seng_setsockopt(udp_con, SOL_SOCKET, SO_RCVTIMEO, (void *)&to, sizeof(to)) < 0) {
					printf("[Enclave] seng_setsockopt failed\n");
				} else {
					ret = seng_recv(udp_con, buf2, sizeof(buf2)-1, 0);
					// note: seems that EAGAIN == EWOULDBLOCK
					if (errno == EAGAIN || errno == EWOULDBLOCK) {
						printf("[Enclave] receive timeout (%d)\n", errno);
					}
					printf("[Enclave] seng_recv: %d\n", ret);
					if (ret > 0) {
						buf2[ret] = '\0';
						printf("[Enclave] Received message: %s\n", buf2);
					}
				}

			}
			seng_close(udp_con);
		}
	}

	// Test of SGX SDK Synchronization Primitives (w/o sleeping, though)
	sgx_thread_mutex_t mutex;
	sgx_thread_mutex_init(&mutex, nullptr);

	printf("[Enclave] Testing mutex and waiting on a condition variable with SENG-added timeout support\n");
	if (sgx_thread_mutex_lock(&mutex) == 0) {
		printf("[Enclave] Inside critical section\n");

		// timeout demo
		sgx_thread_cond_t cond {};
		sgx_thread_cond_init(&cond, NULL);
		seng_timespec_t ts {
			.tv_sec = 2,
			.tv_nsec = 0
		};
		printf("[Enclave] Going to wait %d seconds\n", ts.tv_sec);
		int ret = sgx_thread_cond_timedwait(&cond, &mutex, &ts);
		if (ret == ETIMEDOUT) printf("[Enclave] Timeout!\n");

		sgx_thread_mutex_unlock(&mutex);
	}

	ret = sgx_thread_mutex_trylock(&mutex);
	if (ret == 0) sgx_thread_mutex_unlock(&mutex);

	sgx_thread_mutex_destroy(&mutex);

	printf("[Enclave] Finishing Enclave ECALL now\n");
}
