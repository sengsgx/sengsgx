#ifndef SENG_SENGSERVER_OPENSSL_HPP
#define SENG_SENGSERVER_OPENSSL_HPP

#include "SSLEngine_OpenSSL.hpp"
#include "PacketForwarder_adapted.hpp"
#include "EnclaveIndex_adapted.hpp"

#include "enc_srv_socks/ClientSocketShadower_adapted.hpp"
#include <thread>

#include <string>
#include <memory>
#include <vector>

#include <netinet/in.h>

#include <uv.h>


namespace seng {
    class SengServerOpenSSL {
    public:
        SengServerOpenSSL(std::string &ip_addr, in_port_t tunnel_port,
                   volatile sig_atomic_t * stop_marker_ptr);
        ~SengServerOpenSSL();
        
        void run();
        // void shutdown_server(); // a lot of clean-up code is missing
        void stop_shadow_server();
    private:
        volatile sig_atomic_t * stop_marker_ptr;
        uv_timer_t watcher_fd;
        static void timer_trmpln(uv_timer_t *h);
        void check_shutdown_signal();
        uint64_t check_period_in_ms;
        static void shutdown_trmpln(uv_handle_t *h, void *arg);
        void shutdown_walker(uv_handle_t *h);
        bool is_shutting_down;
        
        //! IP address of Tunnel welcome Socket
        std::string tunnel_ip;
        //! Port number of Tunnel welcome Socket
        in_port_t tunnel_port;
        union {
            uv_tcp_t *tcp_srv_fd;
            uv_udp_t *udp_srv_fd;
        } welcome_socket;

        //! The associated libUV loop
        uv_loop_t loop;

        //! Interface for pushing/pulling IP packets to/from host NIC
        std::shared_ptr<PacketForwarder> ip_pckt_fwder_sp;
        
        std::shared_ptr<EnclaveIndex> enclave_idx_sp;
        
        //! OpenSSL data structures
        SSLEngineOpenSSL ssl_engine;
        
        //! Server BIO UDP object
        BIO *udp_bio;
        //! Server SSL UDP Object
        SSL *ssl;
        
        void init_event_loop();
        void free_event_loop();
        
        //! Extracts and checks the IAS report at (D)TLS handshake
        //static int ra_verify(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags);
        
        void setup_welcome_socket();
        void setup_udp_srv_socket();
        
        void setup_clisock_shadower_srv();
        void start_shadow_srv_thread();
        
        std::unique_ptr<CliSockShadower> shadower_service_up;
        std::thread shadow_service_thread;
    
        void start_event_loop();
        
        //! UV read callback
        static void trmpln_incoming_udp_communication(uv_udp_t *, ssize_t, const uv_buf_t *,
                                                     const struct sockaddr*, unsigned);
        void incoming_udp_communication();
        
        //! Asserts if file descriptor of given handle is in blocking mode, or invalid
        static void check_in_nonblocking_mode(uv_handle_t *);
    };
}

#endif /* SENG_SENGSERVER_OPENSSL_HPP */
