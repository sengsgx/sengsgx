#ifndef SENG_TUNNELNETIF_HPP
#define SENG_TUNNELNETIF_HPP

#include "DT_SSLEngineClient_OpenSSL.hpp"
#include <openssl/ssl.h>

extern "C" {
    #include <lwip/netif.h>
}

namespace seng {
    class TunnelNetif {
    private:
        TunnelNetif();
    
    public:
        // TODO: destructor call?! (does SGX runtime do it nicely?)
        static TunnelNetif &getInstance() {
            static TunnelNetif instance {};
            return instance;
        }

        ~TunnelNetif();

        //! Establish duo DTLS tunnel with NGW
        bool establish_dtls_tunneling();

    private:
        //! MTU of SENG tunnel module (1500B Ethernet MTU - 20 outer IP - 8 outer UDP - <= 40 DTLS)
        static const int TUNNEL_MTU_ETH = 1432;

        //! Created untrusted UDP socket and configures SSL obj
        bool prepare_tunnel_socket (const char *ip, short port,
                                    int *out_sock, SSL **out_ssl);

        //! Performs SSL handshake
        bool connect_tunnel(SSL *tun_ssl);
        //! Receives and acks IP Assignment message of NGW
        bool recv_ip_config();

        err_t netif_init();
        void dummy_recv_loop();
        err_t ip_output(const pbuf *);

    public:
        static err_t netif_init_trmpln (struct netif *);
        static void dummy_netif_input_loop_thread(void *);

// fix prototype and implement
        static err_t ip_output_trmpln(netif*, pbuf*, const ip4_addr*); // ip layer packets
        static err_t linkoutput_not_supported(netif *, pbuf *);

    private:
        //! OpenSSL configs
        SSLEngineClientOpenSSL ssl_engine;
        //! Untrusted UDP sockets
        int send_tun_fd, recv_tun_fd;
        //! Trusted DTLS-SSL objects
        SSL *send_ssl, *recv_ssl;

    public:
        //! Tunnel Config for netif
        ip4_addr_t ipaddr, netmask, gateway;

        struct netif tunnel_mod;
    };
}

#endif /* !SENG_TUNNELNETIF_HPP */
