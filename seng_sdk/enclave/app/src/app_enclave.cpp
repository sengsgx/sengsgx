#include <stdio.h>

#include "app_enclave.h"
#include "app_enclave_t.h"

#include <sgx_spinlock.h>
#include <sgx_thread.h>

#define ETIMEDOUT 110

#include <stdexcept>

#include "seng_api.hpp"
#include "seng_utils.h" // printf is currently here


void t_sgxssl_call_apis()
{
    int ret = 0;
    printf("[Enclave] Start tests\n");

	printf("[Enclave] Try calling the OCALL marked as potential \"switchless\"\n");
	switchless_demo(4711);

	//printf("[Enclave] Going to cause socket() call via BIO_socket() [note BIO_new_socket is safe]\n");
	//sgxssl_socket(2,2,0);
	//int fd = BIO_socket(2, 2, 0, 0); // AF_INET, SOCK_DGRAM

	printf("[Enclave] Trying to init SENG runtime\n");
	if (init_seng_runtime("127.0.0.1", 12345) < 0) {
		printf("[Enclave] Failed to init SENG runtime!\n");
	} else {
		printf("[Enclave] Success! Starting network demo.\n");

		// try seng_socket() via lwIP
		int s_udp_fd = seng_socket(PF_INET,SOCK_DGRAM,0); // (2,2,0)
		int s_udp_fd2 = seng_socket(PF_INET,SOCK_DGRAM,0);
		int s_tcp_fd = seng_socket(PF_INET,SOCK_STREAM,0);
		printf("s_udp_fd = %d\n", s_udp_fd);
		printf("s_udp_fd2 = %d\n", s_udp_fd2);
		printf("s_tcp_fd = %d\n", s_tcp_fd);

		printf("close: %d\n", seng_close(s_udp_fd));
		printf("close: %d\n", seng_close(s_udp_fd2));
		printf("close: %d\n", seng_close(s_udp_fd2));
		printf("close: %d\n", seng_close(s_tcp_fd));

		short demo_port {8391};
		// TODO: adapt accordingly
		const char *demo_ip {"192.168.178.45"};
		printf("[Enclave] Trying to connect to demo target on %s:%d/udp!\n", demo_ip, demo_port);

		int udp_con = seng_socket(PF_INET,SOCK_DGRAM,0);
		//int udp_con = seng_socket(PF_INET,SOCK_DGRAM,0);
		if (udp_con < 0) {
			printf("Faild to create socket\n");
		} else {
			struct sockaddr_in trgt;
			//trgt.sin_len = sizeof(trgt);
			trgt.sin_family = AF_INET;
			trgt.sin_port = lwip_htons(demo_port);
			if (0 == inet_aton(demo_ip, &trgt.sin_addr)) {
				printf("Failed address conversion!\n");
			} else {
				if (-1 == seng_connect(udp_con, (const sockaddr *)&trgt, sizeof(trgt))) {
					printf("Connect failed\n");
				} else {
					const char *buf = "Hello from SDK-SENG!\n";
					printf("payload size: %d\n", strlen(buf));
					int ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
					printf("seng_send: %d\n", ret);
					ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
					printf("seng_send: %d\n", ret);
					ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
					printf("seng_send: %d\n", ret);
					ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
					printf("seng_send: %d\n", ret);
					ret = seng_send(udp_con, buf, strlen(buf), 0); // w/o \0
					printf("seng_send: %d\n", ret);

					char buf2[1510] {};
					buf2[1509] = '\0';
					ret = seng_recv(udp_con, buf2, sizeof(buf2)-1, 0);
					buf2[ret] = '\0';
					printf("seng_recv: %d\n", ret);
					if (ret > 0) {
						printf("received: %s\n", buf2);
					}
					if (ret < 1501) {
						printf("second receive\n");
						ret = seng_recv(udp_con, buf2, sizeof(buf2)-1, 0);
						buf2[ret] = '\0';
						printf("seng_recv: %d\n", ret);
						if (ret > 0) {
							printf("received: %s\n", buf2);
						} 
					}

					// 1,500
					const char *big_data {"EE34567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678FA"};
					//ret = seng_send(udp_con, big_data, strlen(big_data), 0); // w/o \0
					// w/o inner IP fragmentation on UDP commnct.:  1404 B, bcs. 1404 + 20[ip] + 8[udp] = 1432 == netif.mtu
					ret = seng_send(udp_con, big_data, 1404, 0);
					printf("seng_send: %d\n", ret);

					// try lwIP timeout
					struct timeval to {
						.tv_sec = 2,
						.tv_usec = 0,
					};
					if ( seng_setsockopt(udp_con, SOL_SOCKET, SO_RCVTIMEO, (void *)&to, sizeof(to)) < 0) {
						printf("seng_setsockopt failed\n");
					} else {
						ret = seng_recv(udp_con, buf2, sizeof(buf2)-1, 0);
						// note: seems that EAGAIN == EWOULDBLOCK
						if (errno == EAGAIN || errno == EWOULDBLOCK) {
							printf("receive timeout (%d)\n", errno);
						}
						printf("seng_recv: %d\n", ret);
					}

				}
			}
			seng_close(udp_con);
		}
	}

	// Test of SGX SDK Synchronization Primitives (w/o sleeping, though)
	sgx_thread_mutex_t mutex;
	sgx_thread_mutex_init(&mutex, nullptr);

	if (sgx_thread_mutex_lock(&mutex) == 0) {
		printf("[Enclave] Inside critical section\n");

		// timeout demo
		sgx_thread_cond_t cond {};
		sgx_thread_cond_init(&cond, NULL);
		seng_timespec_t ts {
			.tv_sec = 3,
			.tv_nsec = 0
		};
		printf("[Enclave] Going to wait %d seconds\n", ts.tv_sec);
		int ret = sgx_thread_cond_timedwait(&cond, &mutex, &ts);
		if (ret == ETIMEDOUT) printf("Timeout!\n");

		sgx_thread_mutex_unlock(&mutex);
	}

	ret = sgx_thread_mutex_trylock(&mutex);
	if (ret == 0) sgx_thread_mutex_unlock(&mutex);

	sgx_thread_mutex_destroy(&mutex);

	printf("[Enclave] Finishing Enclave ECALL now\n");
}

void second_thread_demo_call() {
	printf("[Enclave] Second ECALL has been called!\n");
	for(int i=0; i<100; i++) {
		if (i==99) printf("[Enclave] Second ECALL almost finished\n");
	}
}

int bench_empty_ecall() {
	return 4711;
}

int bench_switchless_empty_ecall() {
	return 4711;	
}

void bench_ocall(boolean switchless) {
	int retval;
	if(!switchless) {
		for(int i=0;i<500000;i++) empty_ocall(&retval);
	} else {
		for(int i=0;i<500000;i++) empty_switchless_ocall(&retval);
	}
}
