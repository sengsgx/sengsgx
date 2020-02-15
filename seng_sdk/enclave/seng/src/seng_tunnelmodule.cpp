#include "seng_tunnelmodule.hpp"

#include "seng_utils.h"

#include "seng_t.h"

extern "C" {
    #include "seng.pb-c.h"
    #include <lwip/sys.h>
    #include "lwipopts.h"
    #include <lwip/inet.h> // inet_aton define to ip4addr_aton
    #include <lwip/sockets.h> // for struct sockaddr_in
    #include <lwip/netifapi.h> // netifapi_netif_set_link_down
}

//#define TUN_DEBUG

namespace seng {
    TunnelNetif::TunnelNetif() : ssl_engine("ECDHE-RSA-AES256-GCM-SHA384"),
        recv_tun_fd(-1), send_tun_fd(-1), recv_ssl(nullptr), send_ssl(nullptr) {
        ssl_engine.configure();
#ifdef TUN_DEBUG
        printf("[Enclave] Finishing TunnelNetif constructor\n");
#endif
    }

    TunnelNetif::~TunnelNetif() {
        if (send_ssl != nullptr) {
            SSL_shutdown(send_ssl); // TODO: don't call after error!
            SSL_free(send_ssl);
        }
        if (recv_ssl != nullptr) {
            SSL_shutdown(recv_ssl); // TODO: don't call after error!
            SSL_free(recv_ssl);
        }
        // TODO: close sockets
#ifdef TUN_DEBUG
        printf("[Enclave] Finishing TunnelNetif Destructor\n");
#endif
    }

    bool TunnelNetif::establish_dtls_tunneling() {
        // 1st tunnel: send + config
        if (!prepare_tunnel_socket("127.0.0.1", 12345, &send_tun_fd, &send_ssl)
            || !connect_tunnel(send_ssl)) return false;
        if (!recv_ip_config()) return false;

        // 2nd tunnel: recv
        if (!prepare_tunnel_socket("127.0.0.1", 4711, &recv_tun_fd, &recv_ssl)
            || !connect_tunnel(recv_ssl)) return false;

        return true;
    }

    bool TunnelNetif::prepare_tunnel_socket(const char *ip, short port,
                                            int *out_sock, SSL **out_ssl) {
#ifdef TUN_DEBUG
        printf("[Enclave] Requesting socket from untrusted code\n");
#endif
        int sock_fd {-1};
        SSL *tmp_ssl {nullptr};

        sgx_status_t status = setup_tunnel_socket(&sock_fd, port, ip);
        if (status != SGX_SUCCESS || sock_fd < 0) {
            printf("[Enclave] Retrieving untrusted tunnel socket failed\n");
            return false;
        }
	
		BIO *tun_bio = BIO_new_dgram(sock_fd, BIO_NOCLOSE); // BIO_CLOSE choice!, but requires close()
        
		if (tun_bio == nullptr) {
			printf("[Enclave] Failed to setup BIO DGRAM obj\n");
            return false;
		}

        struct sockaddr_in trgt {
            //.sin_len = sizeof(struct sockaddr_in),
            .sin_family = AF_INET,
            .sin_port = lwip_htons(port),
        };
        if (0 == inet_aton(ip, &trgt.sin_addr)) {
            printf("[Enclave] Address convertion failed!\n");
        }
        BIO_ctrl(tun_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &trgt);
#ifdef TUN_DEBUG
        printf("[Enclave] Successfully prepared tunnel socket\n");
#endif

        // SSL Session Object
        tmp_ssl = SSL_new(ssl_engine.ctx);
        if (tmp_ssl == nullptr) {
            BIO_free_all(tun_bio);
            printf("[Enclave] SSL session object creation failed\n");
            return false;
		}
  
        SSL_set_bio(tmp_ssl, tun_bio, tun_bio);
        
        SSL_set_options(tmp_ssl, SSL_OP_NO_QUERY_MTU); // also set at server-side [maybe that's the problem why it sends 1500?!]
        // TODO: does not seem to have an effect if dropping SSL_set_options NO_QUERY_MTU
        if (0 == DTLS_set_link_mtu(tmp_ssl, 1500)) {
            printf("[Enclave] Failed to set DTLS link mtu\n");
        }

/*
        if (0 == DTLS_set_link_mtu(tmp_ssl, 14..)) {
            printf("[Enclave] Failed to set DTLS link mtu\n");
        }
*/

      // Configure receive timeout
        struct timeval {
            long tv_sec;
            long tv_usec;
        };
        // TODO: what value makes sense here?? -- it kind of depends on app code I think; ++ @ handshake no effect (by design)
        //      maybe none is needed, but auto re-handshake is sufficient (-> cf. SSL_MODE_AUTO_RETRY below)
        struct timeval timeout;
        timeout.tv_sec = 120;
        timeout.tv_usec = 0;

#ifdef TUN_DEBUG
        //printf("[Enclave] timeout setting\n");
#endif

        // WARNING: SSL_ctrl() only calls BIO_ctrl() on rbio IF SSL BIO is used,
        //          which we currently DO NOT DO;
        //          so use BIO_ctrl(tun_bio) rather than SSL_ctrl() here!

        int ret;
/*
        // TODO: under sgx-gdb, this has caused EINTR on recv() in the past for unknown reasons
        // -- does not happen if running w/o sgx-gdb
        if (1 != (ret = BIO_ctrl(tun_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout))) {
            printf("[Enclave] Setting timeout failed: %d\n", ret);
        }

        if (1 != BIO_ctrl(tun_bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout)) {
            printf("[Enclave] Setting timeout failed\n");
        }

        printf("[Enclave] stop timeout setting\n");
*/


        /* TODO:
        * I don't think we should enable that, bcs. we don't support reconnections
        * currently @ NGW-side!
        * though I'm not sure whether this might also just include new handshakes?
        */
        SSL_set_mode(tmp_ssl, SSL_MODE_AUTO_RETRY);
#ifdef TUN_DEBUG
        printf("[Enclave] SSL Obj ready and connected to socket\n");
#endif

        // transfer changes
        *out_sock = sock_fd;
        *out_ssl = tmp_ssl;
        return true;
    }

    bool TunnelNetif::connect_tunnel(SSL *tun_ssl) {
#ifdef TUN_DEBUG
        printf("[Enclave] Start handshake\n");
#endif
        // Try to perform the SSL handshake
        int ret = SSL_connect(tun_ssl); // --> sgxssl_write!
        if (ret <= 0) {
            auto ssl_err = SSL_get_error(tun_ssl, ret);
            printf ("Handshake failed with SSL Error: %d\n", ssl_err);
            return false;
        }
        // TODO: non-blocking mode
#ifdef TUN_DEBUG
        printf("[Enclave] Finished handshake\n");
#endif
        return true;
    }


    bool TunnelNetif::recv_ip_config() {   
        uint8_t buf[64] {};
        size_t mlen {0};

        // Receive IP Assign Message
        SengProto__IpAssignment *ip_msg {};
        int ret {-1};
        
        ret = SSL_read(send_ssl, buf, sizeof(buf));
        ip_msg = seng_proto__ip_assignment__unpack(nullptr, ret, buf);
        if (ip_msg == nullptr) {
            printf("Failed to parse IP Assign message\n");
            return false;
        }
        
        // Save for later
        ipaddr = {ip_msg->ip};
        netmask = {ip_msg->netmask};
        gateway = {ip_msg->gw_ip};

/*
        printf("ipaddr: %s,", ip4addr_ntoa(&ipaddr));
        printf(" netmask: %s,", ip4addr_ntoa(&netmask));
        printf(" gateway: %s\n", ip4addr_ntoa(&gateway));
*/

        // Prepare ACK Message
        SengProto__IpAssignACK ack_msg = SENG_PROTO__IP_ASSIGN_ACK__INIT;
        ack_msg.ip = ip_msg->ip;
        mlen = seng_proto__ip_assign_ack__pack(&ack_msg, buf);
        ret = SSL_write(send_ssl, buf, mlen);

        // Free IP Assign Message
        seng_proto__ip_assignment__free_unpacked(ip_msg, nullptr);

        return true;
    }

    err_t TunnelNetif::netif_init_trmpln (struct netif *netif) {
        TunnelNetif &tn = TunnelNetif::getInstance();
        if(&tn.tunnel_mod != netif) return ERR_IF;
        return tn.netif_init();
    }

    err_t TunnelNetif::netif_init() {
        tunnel_mod.state = this;
        tunnel_mod.name[0] = 'f';
        tunnel_mod.name[1] = 'a';
        tunnel_mod.output = TunnelNetif::ip_output_trmpln; // ip layer packets
        tunnel_mod.linkoutput = TunnelNetif::linkoutput_not_supported; // we don't need it, and lwIP only calls output
        tunnel_mod.mtu = TUNNEL_MTU_ETH;

        /* (We just fake an address...) -- TODO: should just remove it */
        tunnel_mod.hwaddr[0] = 0xde;
        tunnel_mod.hwaddr[1] = 0xad;
        tunnel_mod.hwaddr[2] = 0xbe;
        tunnel_mod.hwaddr[3] = 0xef;
        tunnel_mod.hwaddr[4] = 0x24;
        tunnel_mod.hwaddr[5] = 0x09;
        tunnel_mod.hwaddr_len = 6;
        
        /* device capabilities */
        tunnel_mod.flags = 0;

        // low level initialization

        // set link up
        netif_set_link_up(&tunnel_mod);

        // configure tunnel module IP and co. (received from NGW)
        netif_set_addr(&tunnel_mod, &ipaddr, &netmask, &gateway);

#ifdef TUN_DEBUG
        printf("trying to spawn another thread\n");
#endif
        // spawn thread for input loop
        struct sys_thread *s = sys_thread_new("dtlsif_thread", TunnelNetif::dummy_netif_input_loop_thread, NULL,
            DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
        if (s == nullptr) {
            netif_set_link_down(&tunnel_mod);
            throw std::runtime_error("Failed to spawn netif-recv thread");
            //return ERR_IF;
        }

        return ERR_OK;
    }

    err_t TunnelNetif::ip_output_trmpln(netif *netif, pbuf *p, const ip4_addr *ipaddr) {
        (void *)(netif);
        (void *)(ipaddr);
        if (p == nullptr) return ERR_ARG;
        return TunnelNetif::getInstance().ip_output(p);
    }

    err_t TunnelNetif::ip_output(const pbuf *p) {
        // as lwIP thread directly calls into it
        LWIP_ASSERT_CORE_LOCKED();
        assert (p != nullptr);

        // lwIP IP packets should be <= netif.mtu
        unsigned char send_buffer[TUNNEL_MTU_ETH]; // lwIP IP packets should follow mtu [Q: +/- ethernet?]
        if ( unlikely(p->tot_len > sizeof(send_buffer))) {
            printf("dtlsif: packet too large");
            return ERR_IF;
        }

        u16_t copied = pbuf_copy_partial(p, send_buffer, p->tot_len, 0);
        if ( unlikely(copied == 0) ) {
            printf("dtlsif: failed to copy pbuf data into send buffer");
            return ERR_IF;
        }
        // TODO: ERR_IF?
        if ( unlikely(copied < p->tot_len) ) {
            printf("[WARNING]: could not copy all pbuf bytes");
        }

        int ret, ssl_err;
        u16_t len = copied;
        
        // send the IP packet || TODO: blocking vs non-blocking?!    
        do {
            //ERR_clear_error();
            ret = SSL_write( send_ssl, send_buffer, len );
            if ( likely(ret > 0) ) break;
            ssl_err = SSL_get_error(send_ssl, ret);
        }
        while( ssl_err == SSL_ERROR_WANT_READ ||
              ssl_err == SSL_ERROR_WANT_WRITE );  // until done
        
        // TODO: error handling        
        if( unlikely(ret < 0) ) {
            printf("SSL_write error\n");
            netif_set_link_down(&tunnel_mod);
            return ERR_IF;
        }

        return ERR_OK;
    }

    err_t TunnelNetif::linkoutput_not_supported(netif *netif, pbuf *p) {
        (void *)(netif);
        (void *)(p);
//        LWIP_DEBUGF(DTLSIF_DEBUG, ("[DTLS] linkoutput() was called, so we ended up in linkoutput_not_supported()\n"));
        return ERR_IF;
    }


    void TunnelNetif::dummy_netif_input_loop_thread(void *arg) {
        (void *)(arg);
        TunnelNetif::getInstance().dummy_recv_loop();
    }

    void TunnelNetif::dummy_recv_loop() {
        struct pbuf *p {};
        /* Ethernet MTU: 1500; outer headers removed: -20B IP, -8B UDP; 1472 Bytes */
        // 1472B - <DTLS_overhead> (currnetly: ~ 37B w/o compression) is buffer size requirement
        // NOTE: received packets could in theory be slightly larger than netif.mtu as DTLS overhead is usually smaller 40B,
        //       but lwIP does not take netif.mtu into account when receiving IP packets;
        unsigned char recv_buffer[1472]; // leave space for varying DTLS overhead
        uint32_t recv_length { sizeof(recv_buffer) };
        int ret {-1}, ssl_err {-1};

        for (;;) {
            ret = SSL_read(recv_ssl, recv_buffer, recv_length);
            if (likely(ret > 0)) {
                p = pbuf_alloc(PBUF_RAW, ret, PBUF_POOL); 
                if (likely(p)) {
                    pbuf_take(p, recv_buffer, ret);
                    if (tunnel_mod.input(p, &tunnel_mod) == ERR_OK) continue;
                    
                    pbuf_free(p);
                    p = nullptr;
                } else {
                    // todo
                }
                printf("pushing IP packet to lwIP failed: %s\n", p ? "mbox full?" : "OOM");
                continue;
            }

            // ret <= 0
            printf("dummy_recv_loop: SSL error -- <= 0 returned\n");
            ssl_err = SSL_get_error(recv_ssl, ret);
            if (likely(ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE)) {
                continue;
            } else {
                printf("Receive loop error: %d (%d)\n", ret, ssl_err);
                netifapi_netif_set_link_down(&tunnel_mod);
                break;
            }
        }
    }


    extern "C" int input_tunnel_packet(const void *buf, size_t len) {
        TunnelNetif &tn = TunnelNetif::getInstance();
        // TODO
        return -1;
    }
}

