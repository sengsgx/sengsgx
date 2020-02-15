#ifndef SENG_LWIP_OPTS_H
#define SENG_LWIP_OPTS_H

#define LWIP_NOASSERT 1

/* setting this to 1 (default is 0) kills performance */
/* this is still the case; Apache @ Middlebox --> setting this to 1 makes it noch reach below 10 sec anymore; 8.9-9.5 otherwise */
#define LWIP_TCPIP_CORE_LOCKING_INPUT 1

#define LWIP_IPV4                   1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_SOCKET                 1

#define LWIP_IPV6                   0

#define LWIP_DEBUG                  1

#define LWIP_DBG_TYPES_ON LWIP_DBG_OFF

/*#define IP_DEBUG LWIP_DBG_ON*/

#define SOCKETS_DEBUG LWIP_DBG_ON

#define NO_SYS                      0
#define LWIP_TCPIP_CORE_LOCKING     1 /* 1 --> client grabs core locks sometimes */

#if !NO_SYS
void sys_check_core_locking(void);
#define LWIP_ASSERT_CORE_LOCKED()  sys_check_core_locking()
void sys_mark_tcpip_thread(void);
#define LWIP_MARK_TCPIP_THREAD()   sys_mark_tcpip_thread()

#if LWIP_TCPIP_CORE_LOCKING
void sys_lock_tcpip_core(void);
#define LOCK_TCPIP_CORE()          sys_lock_tcpip_core()
void sys_unlock_tcpip_core(void);
#define UNLOCK_TCPIP_CORE()        sys_unlock_tcpip_core()
#endif
#endif

#define DTLSIF_DEBUG LWIP_DBG_ON
#define NETIF_DEBUG LWIP_DBG_ON
#define UDP_DEBUG LWIP_DBG_ON
#define TCP_DEBUG LWIP_DBG_ON
#define API_MSG_DEBUG LWIP_DBG_ON
#define PBUF_DEBUG LWIP_DBG_ON
#define API_LIB_DEBUG LWIP_DBG_ON

/*#define LWIP_ARP                    0*/
#define LWIP_ARP                    0
#define LWIP_ETHERNET               0

#define MIB2_STATS                  0
#define LINK_STATS                  0

#define LWIP_SINGLE_NETIF           1

#define LWIP_NETIF_LOOPBACK         1
#define LWIP_HAVE_LOOPIF            0

/*#define IP_FORWARD                  1*/

#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

/* enable netifapi functions */
#define LWIP_NETIF_API 1

#define MAX_LWIP_SOCKETS	150
#define LWIP_SOCKET_OFFSET 	(1024) /*(FD_SETSIZE - MAX_LWIP_SOCKETS)*/ /* seems to fetch 512 rather than 1024  for FD_SETSIZE */
#define MEMP_NUM_NETCONN	MAX_LWIP_SOCKETS
#define LWIP_COMPAT_SOCKETS	0

#define MEMP_NUM_UDP_PCB	MAX_LWIP_SOCKETS
#define MEMP_NUM_TCP_PCB	MAX_LWIP_SOCKETS

/*
#define LWIP_NETCONN_SEM_PER_THREAD 1

-> requires arch-specific implementations
-> samples only exist for contrib/{win32,freertos},
   not for UNIX
*/

#define LWIP_FIONREAD_LINUXMODE	1

#define LWIP_DNS		1


#define LWIP_SO_RCVBUF 		1
#define LWIP_SO_RCVTIMEO        1
#define LWIP_SO_SNDTIMEO        1


#define SO_REUSE              	1

#define MEMP_NUM_NETDB        	8
/*
#define DNS_DEBUG LWIP_DBG_ON
*/

#define LWIP_TCP_KEEPALIVE	1

/*#define TCP_MSS             1380*/ /*1380*/ /* assuming using TLS with 20TCP, <=40TLS, and inner TCP connection*/ /*536*/
#define TCP_MSS             1392 /* DTLS -> UDP hdr is 12 B smaller than TCP hdr */
/* increase in case of high receiving loads per connection */
#define TCP_WND            (8 * TCP_MSS) /* default: (4 * TCP_MSS) */
#define LWIP_WND_SCALE      1
#define TCP_RCV_SCALE       1

#define PBUF_POOL_SIZE      100 /* default: 16 */
#define PBUF_POOL_BUFSIZE               LWIP_MEM_ALIGN_SIZE(TCP_MSS+20+20+40) /*1460*/

#define LWIP_TCP_SACK_OUT   1 /*1*/ /* important to enable to avoid huge retransmissions and unpredictable bandwidth */
#define LWIP_TCP_MAX_SACK_NUM 4 /* default is 4, and more than 4 seems to have limited effects, but "is not pointless" according to doc */

#define TCP_SND_BUF         (4 * 4 * TCP_MSS) /*TCP_WND*/ /*(2 * TCP_MSS)*/
#define TCP_SND_QUEUELEN    ((4 * 8 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS)) /*((4 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS)) */ /* has to be => 2*SND_BUF/MSS */
#define MEMP_NUM_TCP_SEG    (4 * 2 * TCP_SND_QUEUELEN) /*(2 * TCP_SND_QUEUELEN)*/ /*16*/ /* has to be >= SND_QUEUELEN */

/* Heap size used with mem_malloc() and pbuf_alloc(*, PBUF_RAM); for outgoing packets mostly */
/* consider increasing in case of higher sending loads */
#define MEM_SIZE  (80 * 4096)

#define CHECKSUM_GEN_IP     1
#define CHECKSUM_GEN_UDP    1
#define CHECKSUM_GEN_TCP    1
#define CHECKSUM_CHECK_IP   0 /*1 all 3*/
#define CHECKSUM_CHECK_UDP  0
#define CHECKSUM_CHECK_TCP  0
/* NOTE: also exists for ICMP */

/* to avoid potential malicious encodings under untrusted time (0 is lwIP default value anyway) */
#define LWIP_TCP_TIMESTAMPS 0

/*
TCP_SND_BUF
TCP_SND_QUEUELEN
*/

#endif
