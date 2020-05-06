#ifndef MYDEMO_LWIP_OPTS_H
#define MYDEMO_LWIP_OPTS_H

#define LWIP_NOASSERT 1

#define LWIP_TCPIP_CORE_LOCKING_INPUT 0

#define LWIP_IPV4                   1
#define LWIP_TCP                    1
#define LWIP_UDP                    1
#define LWIP_SOCKET                 1

#define LWIP_IPV6                   0

#define LWIP_DEBUG                  1

#define LWIP_DBG_TYPES_ON LWIP_DBG_OFF

/*#define IP_DEBUG LWIP_DBG_ON*/

#define SOCKETS_DEBUG LWIP_DBG_ON
#define TAPIF_DEBUG LWIP_DBG_ON

#define NO_SYS                      0
#define LWIP_TCPIP_CORE_LOCKING     1

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

#define LWIP_ARP                    0
#define LWIP_ETHERNET               0

#define MIB2_STATS                  0
#define LINK_STATS                  0

#define LWIP_SINGLE_NETIF           1

#define LWIP_NETIF_LOOPBACK         1
#define LWIP_HAVE_LOOPIF            0

/*#define IP_FORWARD                  1*/

/* get rid of lwIP's htons() and co. */
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

/* enable netifapi functions */
#define LWIP_NETIF_API 1

#define MAX_LWIP_SOCKETS	512
#define LWIP_SOCKET_OFFSET 	(FD_SETSIZE - MAX_LWIP_SOCKETS)
#define MEMP_NUM_NETCONN	MAX_LWIP_SOCKETS
#define LWIP_COMPAT_SOCKETS	0

#define MEMP_NUM_UDP_PCB	MAX_LWIP_SOCKETS
#define MEMP_NUM_TCP_PCB	MAX_LWIP_SOCKETS

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

#define TCP_MSS             1380
/* Sample Configurations:
 * local testing:     12000 TCP_WND,   15 pools
 * default:          104000 TCP_WND,   80 pools, scale 1
 * external target: 4096000 TCP_WND, 3000 pools, scale 7
 */
#define TCP_WND            104000
#define LWIP_WND_SCALE      1
#define TCP_RCV_SCALE       1 /* 7 */

#define PBUF_POOL_SIZE      80 /* 190 */ /*3000*/

#define PBUF_POOL_BUFSIZE               LWIP_MEM_ALIGN_SIZE(TCP_MSS+20+20+40)

#define LWIP_TCP_SACK_OUT   1 /*1*/ /* important to enable to avoid huge retransmissions and unpredictable bandwidth */
#define LWIP_TCP_MAX_SACK_NUM 4

#define TCP_SND_BUF         (4 * 4 * TCP_MSS)
#define TCP_SND_QUEUELEN    ((4 * 8 * (TCP_SND_BUF) + (TCP_MSS - 1))/(TCP_MSS))
#define MEMP_NUM_TCP_SEG    (4 * 2 * TCP_SND_QUEUELEN)

/* IP fragmentation */
/*
#define IP_REASS_MAX_BUFS 50
#define IP_REASS_MAXAGE 20
#define MEMP_NUM_REASSDATA 5
*/

/* Heap size used with mem_malloc() and pbuf_alloc(*, PBUF_RAM); for outgoing packets mostly */
#define MEM_SIZE (4 * 92160)

#define CHECKSUM_GEN_IP     1
#define CHECKSUM_GEN_UDP    1
#define CHECKSUM_GEN_TCP    1

/* Handled by GW + DTLS */
#define CHECKSUM_CHECK_IP   0
#define CHECKSUM_CHECK_UDP  0
#define CHECKSUM_CHECK_TCP  0
/* NOTE: also exists for ICMP */

#endif
