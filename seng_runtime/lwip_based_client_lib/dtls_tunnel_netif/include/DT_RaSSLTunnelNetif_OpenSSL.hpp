#ifndef SENG_RASSL_TUNNELNETIF_OPENSSL_HPP
#define SENG_RASSL_TUNNELNETIF_OPENSSL_HPP

#include <string>
#include <atomic>

#include <iostream> // for ::ios_base

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "DT_SSLEngineClient_OpenSSL.hpp"

extern "C" {
    #include "lwip/netif.h"
}

// experimental
#include <pthread.h>

//#define DTLSIF_DEBUG_PRINTS
#define DTLSIF_PRINT "[dtlsif] "


namespace seng {
    class RaSSLTunnelNetifOpenSSL {
    private:
        // NEW: experimental Singleton to get in on stack
        RaSSLTunnelNetifOpenSSL(struct netif *);
    public:
        static RaSSLTunnelNetifOpenSSL &getInstance() {
            static RaSSLTunnelNetifOpenSSL instance {nullptr};
            return instance;
        }
        void trySetNetifPtr(struct netif *);
        ~RaSSLTunnelNetifOpenSSL();
        
        RaSSLTunnelNetifOpenSSL(RaSSLTunnelNetifOpenSSL &) = delete;
        RaSSLTunnelNetifOpenSSL& operator=(RaSSLTunnelNetifOpenSSL &) = delete;
        RaSSLTunnelNetifOpenSSL(RaSSLTunnelNetifOpenSSL &&) noexcept = delete;
        
        
        /* *************************************** *
         * lwIP Netif-related Attributes + Methods *
         * *************************************** */
        
        static err_t netif_init_trmpln(struct netif *netif);
        static err_t ip_output_trmpln(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
        static err_t linkoutput_not_supported(struct netif *netif, struct pbuf *p);
        
    private:
        struct netif *own_netif_ptr;
        
        err_t netif_init();
        err_t low_level_tunnel_init();
        
        static void netif_input_loop_thread(void *arg);
        void netif_input();
        
        /* glue between netif and tunnel code */
        err_t ip_output_through_tunnel(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr);
        struct pbuf *low_level_ip_input_from_tunnel();
        
        /* ********************************************** *
         * Tunnel Connection-specific Attributes + Methods *
         * ********************************************** */
        
        std::string tunnel_dst_ip;
        std::string tunnel_dst_port;
        
        //! OpenSSL data structures
        SSLEngineClientOpenSSL ssl_engine;
        
        //! Connection to Middlebox via RA-DTLS channel
        BIO *tunnel_socket_bio;
        //! For sending to NGW
        SSL *ssl;
        //! For receiving packets from NGW
        SSL *recv_ssl;
        
        bool ssl_needs_shutdown, recv_needs_shutdown;
        
        //! For notifying close to netif thread
        int notification_sockets[2];
#define SEND_NOTIFY (0)
#define WAIT_FOR_NOTIFY (1)
        
        // "it is guaranteed to be lock-free"; "A spinlock mutex can be implemented in userspace using an atomic_flag" ~ https://en.cppreference.com/w/cpp/atomic/atomic_flag
        //! if set then tunnel is open; cleared otherwise; checkers have to re-clear;
        std::atomic_flag spinlock__tunnel_is_open;
        
        void establish_ssl_session_and_set_link_up();
        void show_certificate_verification_results(SSL *ssl_obj);
        void show_sgx_quote_info(SSL *ssl_obj);
        
        void receive_ip_configuration();
        
        //! Marks tunnel as closed and informs netif and lwIP thread
        void close_tunnel_connection();
        
        void inform_netif();
        void mark_closed_inform();
        
    public:
        //! Informs netif thread, which will wait till timeout or error before closing
        void locked__graceful_shutdown();

        pthread_t netif_rloop_thread_id;
        
    /* ********************************************************************** */
        
    private:
        // needed together with init_priority() to ensure std::cout got initialized
        std::ios_base::Init mInitializer;
    };
}

#endif /* SENG_RASSL_TUNNELNETIF_HPP */
