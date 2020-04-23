#include "DT_RaSSLTunnelNetif_OpenSSL.hpp"

#include <iostream>
#include <stdexcept>
#include <limits>

#include <sys/socket.h>
#include <unistd.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/epoll.h>

#include <sgx_quote.h>

#include <hooks/sockets.hpp>


extern "C" {
    #include <ra-attester.h>
    #include <ra-challenger.h>
}

extern "C" {
    #include "lwip/debug.h"
    #include "lwip/sys.h"
    
    #include "lwip/ip.h"
    #include "lwip/pbuf.h"
    
    #include "lwip/netif.h"
    #include "lwip/netifapi.h"
}

#include "seng.pb.h"

extern "C" {
    #include "th-lock.h"
}

// mainly for testing
#define RELAXED_ERROR_HANDLING


// experimental, bcs. private
struct sys_thread {
    struct sys_thread *next;
    pthread_t pthread;
};

namespace seng {
    void RaSSLTunnelNetifOpenSSL::trySetNetifPtr(struct netif *p) {
        if (own_netif_ptr == nullptr) own_netif_ptr = p;
    }
    
    RaSSLTunnelNetifOpenSSL::RaSSLTunnelNetifOpenSSL(struct netif *netif) :
    tunnel_dst_ip("127.0.0.1"),
    tunnel_dst_port("12345"), ssl_engine("ECDHE-RSA-AES256-GCM-SHA384", "middlebox_cert.pem"), own_netif_ptr(netif), ssl(nullptr), recv_ssl(nullptr), tunnel_socket_bio(nullptr), ssl_needs_shutdown(true), recv_needs_shutdown(true),
    netif_rloop_thread_id(), spinlock__tunnel_is_open(ATOMIC_FLAG_INIT)
    {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Constructor of RaSSLTunnelNetifOpenSSL called" << std::endl;
        std::cout.flush();
#endif

        // Socket Pair for netif thread
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, notification_sockets) != 0) {
            perror("socketpair");
            throw std::runtime_error("Failed to create socketpair");
        }
        
        // currently not required anymore bcs of change to exp. singleton
        //assert (netif != nullptr);
        ssl_engine.configure();
    }
    
    RaSSLTunnelNetifOpenSSL::~RaSSLTunnelNetifOpenSSL() {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cerr << "DESTRUCTED!" << std::endl;
        std::cerr.flush();
#endif
        
        if (spinlock__tunnel_is_open.test_and_set()) {
            close_tunnel_connection();
        } else {
            spinlock__tunnel_is_open.clear();
        }
        
        close(notification_sockets[SEND_NOTIFY]);
        close(notification_sockets[WAIT_FOR_NOTIFY]);
        if (ssl != nullptr) {
            // Note: SSL_shutdown() is disallowed in some error cases!
            if (ssl_needs_shutdown) SSL_shutdown(ssl); // TODO: blocking timeout loop? -- timeout not yet supported for UDP by Graphene!
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (recv_ssl != nullptr) {
            // Note: SSL_shutdown() is disallowed in some error cases!
            if (recv_needs_shutdown) SSL_shutdown(recv_ssl); // TODO: blocking timeout loop? -- timeout not yet supported for UDP by Graphene!
            SSL_free(recv_ssl);
            recv_ssl = nullptr;
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cerr << "DONE with destruction!" << std::endl;
        std::cerr.flush();
#endif
    }
    
    void
    RaSSLTunnelNetifOpenSSL::mark_closed_inform() {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Signalling close via spinlock" << std::endl;
        std::cout.flush();
#endif
        
        // Notify input and output(+lwIP) functions
        spinlock__tunnel_is_open.clear();
    }
    
    void
    RaSSLTunnelNetifOpenSSL::inform_netif() {
        // Notify epoll() netif thread
        char buf[1] {'\0'};
        
        int ret = write(notification_sockets[SEND_NOTIFY], buf, sizeof(buf));
        if (ret != 1) throw std::runtime_error("Failed to send message through notification socket");
    }
    
    void
    RaSSLTunnelNetifOpenSSL::close_tunnel_connection() {
        assert (spinlock__tunnel_is_open.test_and_set());
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Closing Tunnel Connection" << std::endl;
        std::cout.flush();
#endif
        
        mark_closed_inform();
        inform_netif();
    }
    
    void
    RaSSLTunnelNetifOpenSSL::locked__graceful_shutdown() {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Graceful Shutdown Request" << std::endl;
        std::cout.flush();
#endif
        
        // already marked as closed
        if (!spinlock__tunnel_is_open.test_and_set()) {
            spinlock__tunnel_is_open.clear();
            return;
        }
        // TODO: here might be a time window where multiple might try to close! must ensure that doesn't break things!
        //close_tunnel_connection();
        
        inform_netif();
    }

    void
    RaSSLTunnelNetifOpenSSL::establish_ssl_session_and_set_link_up() {
        // as we call from lwIP thread during init
        LWIP_ASSERT_CORE_LOCKED();
        
        assert (!netif_is_link_up(own_netif_ptr));
        //assert (locked__tunnel_is_closed); // TODO: might change when reconnection support is integrated
        
        // Create TCP/UDP connection to NGW server
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Connecting to " << tunnel_dst_ip << ":" << tunnel_dst_port << "..." << std::endl;
        std::cout.flush();
#endif

        // Create UDP Socket
        int udp_sock = seng_socket(AF_INET, SOCK_DGRAM, 0);
        if (udp_sock < 0) {
            std::cout << "UDP Socket Creation Failed" << std::endl;
            std::cout.flush();
            throw std::runtime_error("UDP Socket Creation failed!");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "UDP Socket created" << std::endl;
        std::cout.flush();
#endif
        
        auto port = (unsigned int) std::stoi(tunnel_dst_port);
        if (port > std::numeric_limits<short>::max()) {
            close(udp_sock);
            throw std::runtime_error("Port invalid!");
        }
        
        struct sockaddr_in target {
            .sin_family = AF_INET,
            .sin_port = htons((short) port),
            .sin_addr = {0}
        };
        if (inet_aton(tunnel_dst_ip.c_str(), &target.sin_addr) < 0) {
            close(udp_sock);
            throw std::runtime_error("inet_aton() failed");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Target address prepared" << std::endl;
        std::cout.flush();
#endif
        
        if(connect(udp_sock, (struct sockaddr *)&target, sizeof(target)) < 0) {
            close(udp_sock);
            throw std::runtime_error("UDP Connect to SENG Server failed");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "UDP Socket connect() done" << std::endl;
        std::cout.flush();
#endif

        // UDP Bio object
        tunnel_socket_bio = BIO_new_dgram(udp_sock, BIO_CLOSE);
        if (tunnel_socket_bio == nullptr) {
            close(udp_sock);
            throw std::runtime_error("Datagram BIO creation failed");
        }
        
        /* Set and activate timeouts */
        struct timeval timeout {
            .tv_sec = 5,
            .tv_usec = 0
        };

        // TODO: currently timeouts only supported for UDP by Graphene-SGX
     //   BIO_ctrl(tunnel_socket_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
       // BIO_ctrl(tunnel_socket_bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        
        /*if (setsockopt(udp_sock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&timeout,sizeof(struct timeval)) < 0) {
            perror("SO_RCVTIMEO UDP");
            std::cerr.flush();
            std::cout.flush();
        }
        if (setsockopt(udp_sock, SOL_SOCKET, SO_SNDTIMEO,(struct timeval *)&timeout,sizeof(struct timeval)) < 0) {
            perror("SO_SNDTIMEO UDP");
            std::cerr.flush();
            std::cout.flush();
        }*/
        
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << " ok" << std::endl;
        std::cout.flush();
#endif
        
        // DTLS/SSL Object + link it to UDP Socket BIO
        ssl = SSL_new(ssl_engine.ctx);
        if (ssl == nullptr) {
            BIO_free_all(tunnel_socket_bio);
            //close(udp_sock); -- BIO_CLOSE
            throw std::runtime_error("SSL session object creation failed");
        }
        
        DTLS_set_link_mtu(ssl, 1500);
        
        // IMPORTANT!
        BIO_ctrl(tunnel_socket_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &target);
        
        SSL_set_bio(ssl, tunnel_socket_bio, tunnel_socket_bio);
        
        // I don't think we should enable that, bcs. we don't support reconnections currently @ NGW-side!
        // though I'm not sure whether this might also just include new handshakes?
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
 
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Trying to perform SSL handshake" << std::endl;
        std::cout.flush();
#endif
        
        // Try to perform the SSL handshake
        int ret = SSL_connect(ssl);
        if (ret <= 0) {
            auto ssl_err = SSL_get_error(ssl, ret);
            std::cerr << "Handshake failed with SSL Error: " << ssl_err << std::endl;
            std::cout << "SSL_ERROR_SSL: " << SSL_ERROR_SSL << ", SSL_ERROR_SYSCALL: " << SSL_ERROR_SYSCALL << std::endl;
            
            /* "SSL_shutdown() must not be called." ~ man page */
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                ssl_needs_shutdown = false;
            }
            throw std::runtime_error("SSL handshake with SENG Server failed");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Finished SSL handshake" << std::endl;
        std::cout.flush();
#endif
        
#ifdef DTLSIF_DEBUG_PRINTS
        // debug print certificate state
        show_certificate_verification_results(ssl);
        
        // debug print SGX quote/report
        show_sgx_quote_info(ssl);
#endif
        
        receive_ip_configuration();
        
        // set to nonblocking mode as we will now start doing read/write in (lock-protected) parallel
        BIO_set_nbio(tunnel_socket_bio, 1); // "always returns 1"
        
        /* Create 2nd DTLS tunnel connection for receving ! */
        int recv_udp = seng_socket(AF_INET, SOCK_DGRAM, 0);
        if (recv_udp < 0) {
            std::cout << "2nd UDP Socket Creation Failed" << std::endl;
            std::cout.flush();
            throw std::runtime_error("SSL handshake with SENG Server failed");
        }
        
        target.sin_port = htons(4711);

        if(connect(recv_udp, (struct sockaddr *)&target, sizeof(target)) < 0) {
            close(recv_udp);
            throw std::runtime_error("2nd UDP Connect to SENG Server failed");
        }

        // UDP Bio object
        BIO *recv_bio = BIO_new_dgram(recv_udp, BIO_CLOSE);
        if (recv_bio == nullptr) {
            close(recv_udp);
            throw std::runtime_error("Datagram BIO creation failed");
        }

        // TODO: not yet supported for UDP by Graphene-SGX
        /*
        BIO_ctrl(recv_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        BIO_ctrl(recv_bio, BIO_CTRL_DGRAM_SET_SEND_TIMEOUT, 0, &timeout);
        */
         
        // DTLS/SSL Object + link it to 2nd UDP Socket BIO
        recv_ssl = SSL_new(ssl_engine.ctx);
        if (recv_ssl == nullptr) {
            BIO_free_all(recv_bio);
            throw std::runtime_error("SSL session object creation failed");
        }
        
        DTLS_set_link_mtu(recv_ssl, 1500);
        
        // IMPORTANT!
        BIO_ctrl(recv_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &target);
        
        SSL_set_bio(recv_ssl, recv_bio, recv_bio);
        
        SSL_set_mode(recv_ssl, SSL_MODE_AUTO_RETRY);
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Trying to perform 2nd DTLS handshake" << std::endl;
        std::cout.flush();
#endif
        
        // Try to perform the SSL handshake
        ret = SSL_connect(recv_ssl);
        if (ret <= 0) {
            auto ssl_err = SSL_get_error(recv_ssl, ret);
            std::cerr << "2nd Handshake failed with SSL Error: " << ssl_err << std::endl;
            std::cout << "SSL_ERROR_SSL: " << SSL_ERROR_SSL << ", SSL_ERROR_SYSCALL: " << SSL_ERROR_SYSCALL << std::endl;
            std::cerr.flush();
            std::cout.flush();
            
            /* "SSL_shutdown() must not be called." ~ man page */
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                recv_needs_shutdown = false;
            }
            
            throw std::runtime_error("SSL handshake with SENG Server failed");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        show_certificate_verification_results(recv_ssl);
        show_sgx_quote_info(recv_ssl);
#endif
      
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "2nd DTLS handshake Done." << std::endl;
        std::cout.flush();
#endif
        
        BIO_set_nbio(recv_bio, 1);
        
        if (spinlock__tunnel_is_open.test_and_set()) {
            throw std::runtime_error("tunnel was already open");
        }
        
        netif_set_link_up(own_netif_ptr);
    }

    void
    RaSSLTunnelNetifOpenSSL::show_certificate_verification_results(SSL *ssl_obj) {
        std::cout << DTLSIF_PRINT "Results of server certificate verification:";
        
        // NOTE: this returns result based on standard cert_verify_callback, not on
        //      custom callback set via set_verify()
        if(SSL_get_verify_result(ssl_obj) == X509_V_OK) {
            std::cout << " ok" << std::endl;
            
        } else {
            std::cout << " failed" << std::endl;
            std::cout << SSL_get_verify_result(ssl_obj) << std::endl;
        }
    }
    
    void
    RaSSLTunnelNetifOpenSSL::show_sgx_quote_info(SSL *ssl_obj) {
        X509 *cli_cert = SSL_get_certificate(ssl_obj);
        
        int der_len = i2d_X509(cli_cert, NULL);
        assert(der_len > 0);
        
        unsigned char der[der_len];
        unsigned char *p = der;
        i2d_X509(cli_cert, &p);
        
        sgx_quote_t quote;
        get_quote_from_cert(der, der_len, &quote);
        
        sgx_report_body_t* body = &quote.report_body;
        assert (body != nullptr);
        
        char mrenclave_hex_str[SGX_HASH_SIZE * 2 + 1] {0,};
        char mrsigner_hex_str[SGX_HASH_SIZE * 2 + 1] {0,};
        for (int i = 0; i < SGX_HASH_SIZE; ++i) {
            sprintf(&mrenclave_hex_str[i * 2], "%02x", body->mr_enclave.m[i]);
            sprintf(&mrsigner_hex_str[i * 2], "%02x", body->mr_signer.m[i]);
        }
        
        std::cout << DTLSIF_PRINT "Successful connection using:" << std::endl
        << DTLSIF_PRINT "MRENCLAVE: "  << mrenclave_hex_str << std::endl
        << DTLSIF_PRINT "MRSIGNER: "   << mrsigner_hex_str << std::endl;
        std::cout.flush();
    }
    
    void
    RaSSLTunnelNetifOpenSSL::receive_ip_configuration() {
        // TODO: timeout-retransmit mechanism for DTLS
        
        unsigned char buf[30];
        int ret, ssl_err;
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Trying to receive Internal IP" << "...";
        std::cout.flush();
#endif
        
        do {
            ret = SSL_read(ssl, buf, sizeof(buf));
            ssl_err = SSL_get_error(ssl, ret);
        } while ( ssl_err == SSL_ERROR_WANT_READ ||
               ssl_err == SSL_ERROR_WANT_WRITE );
        if (ret <= 0) {
            /* "SSL_shutdown() must not be called." ~ man page */
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                ssl_needs_shutdown = false;
            }
            throw std::runtime_error("Receiving IP address failed");
        }
        
        seng_proto::IpAssignment ip_msg;
        if ( !ip_msg.ParseFromArray(buf, ret) ) {
            /* "SSL_shutdown() must not be called." ~ man page */
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                ssl_needs_shutdown = false;
            }
            throw std::runtime_error("Failed to parse IP address out of received message");
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << " Done: '" << ip_msg.ip() << "'" << std::endl;
        std::cout.flush();
#endif
        
        ip4_addr_t ipaddr {ip_msg.ip()}, netmask {ip_msg.netmask()}, gateway {ip_msg.gw_ip()};
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Trying to set netif IP, netmask and gateway ..." << std::endl;;
        std::cout.flush();
#endif

        netif_set_addr(own_netif_ptr, &ipaddr, &netmask, &gateway);
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Done." << std::endl;
#endif
        
        // DTLS requires manual ACKing
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Sending IP Assign ACK message ...";
        std::cout.flush();
#endif
        
        seng_proto::IpAssignACK ack_msg;
        ack_msg.set_ip(ip_msg.ip()); // to avoid 0 size buffer
        std::string msg_data;
        bool ret_bool = ack_msg.SerializeToString(&msg_data);
        assert (ret_bool);
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << " of size: " << msg_data.size();
#endif
        
        do {
            // TODO: might be dropped on path ! (cf. above, retransmission loop with timeouts is TODO, but Graphene-SGX does not yet support timeouts for UDP?)
            ret = SSL_write ( ssl, (const unsigned char *)msg_data.data(), msg_data.size() );
            ssl_err = SSL_get_error(ssl, ret);
        }
        while( ssl_err == SSL_ERROR_WANT_READ ||
              ssl_err == SSL_ERROR_WANT_WRITE );
        
        if (ret <= 0) {
            /* "SSL_shutdown() must not be called." ~ man page */
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                ssl_needs_shutdown = false;
            }
            throw std::runtime_error("Failed to send IP ACK message");
        }
        
        assert(ret == msg_data.size());
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << " Done." << std::endl;
#endif
    }
    
    
    /* ********************************************* *
     * lwip-netif callback functions and trampolines *
     * ********************************************* */
    
    err_t
    RaSSLTunnelNetifOpenSSL::netif_init_trmpln(struct netif *netif) {
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "netif_init_trmpln()" << std::endl;
#endif
        //auto tunnel_netif = (RaSSLTunnelNetifOpenSSL *) new(std::nothrow) RaSSLTunnelNetif(netif, SSLType::DTLS);
        RaSSLTunnelNetifOpenSSL *tunnel_netif;
        try {
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
            bool timeofday_ok_init {true};
            struct timeval listen_tv_start_init {}, listen_tv_end_init {};
            if( gettimeofday(&listen_tv_start_init, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
                timeofday_ok_init = false;
            }
#endif
        SSL_load_error_strings();
        SSL_library_init();
        
        CRYPTO_thread_setup();
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
            if( timeofday_ok_init ) {
                if ( gettimeofday(&listen_tv_end_init, nullptr) != 0 ) {
                    fprintf(stderr, "gettimeofday failed in setup\n");
                    fflush(stderr);
                } else {
                    auto diff_sec = listen_tv_end_init.tv_sec - listen_tv_start_init.tv_sec;
                    auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end_init.tv_usec - listen_tv_start_init.tv_usec;
                    printf("%ld;", total_diff_in_ms);
                    //fflush(stdout);
                    //fprintf(stderr, "OpenSSL Library Init (error strings, library, thread)\n");
                    //fflush(stderr);
                }
            }
#endif
            tunnel_netif = &RaSSLTunnelNetifOpenSSL::getInstance();
        } catch (...) {
            tunnel_netif = nullptr;
        }
        if (tunnel_netif == nullptr) {
#ifdef DTLSIF_DEBUG_PRINTS
            std::cerr << "Failed to create RaSSLTunnelNetifOpenSSL" << std::endl;
#endif
            LWIP_DEBUGF(NETIF_DEBUG, ("dtlsif_init: out of memory for dtlsif\n"));
            return ERR_MEM;
        }
        tunnel_netif->trySetNetifPtr(netif);
        netif->state = tunnel_netif;
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Calling netif_init() of TunnelNetif" << std::endl;
#endif
        return tunnel_netif->netif_init();
    }
    
    err_t
    RaSSLTunnelNetifOpenSSL::netif_init() {
        own_netif_ptr->name[0] = 't';
        own_netif_ptr->name[1] = 'u';
        own_netif_ptr->output = RaSSLTunnelNetifOpenSSL::ip_output_trmpln; // ip layer packets
        own_netif_ptr->linkoutput = RaSSLTunnelNetifOpenSSL::linkoutput_not_supported; // we don't need it, and lwIP only calls output
        // TODO: set to appropriate value via IP config msg
        own_netif_ptr->mtu = 1420; // 1500 - 20 (IP) - 20 (TCP) - <= 40 ((D)TLS);

        return low_level_tunnel_init();
    }
    
    err_t
    RaSSLTunnelNetifOpenSSL::low_level_tunnel_init()
    {
        LWIP_DEBUGF(DTLSIF_DEBUG, ("[dtlsif] low_level_init\n"));
        
        /* TODO: should just remove it as we don't use link-layer packets */
        own_netif_ptr->hwaddr[0] = 0xde;
        own_netif_ptr->hwaddr[1] = 0xad;
        own_netif_ptr->hwaddr[2] = 0xbe;
        own_netif_ptr->hwaddr[3] = 0xef;
        own_netif_ptr->hwaddr[4] = 0x24;
        own_netif_ptr->hwaddr[5] = 0x09;
        own_netif_ptr->hwaddr_len = 6;
        
        /* device capabilities */
        own_netif_ptr->flags = 0;
        
        try {
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
            bool timeofday_ok {true};
            struct timeval listen_tv_start {}, listen_tv_end {};
            if( gettimeofday(&listen_tv_start, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
                timeofday_ok = false;
            }
#endif
            // DTLS tunnel establishment + internal IP assignment
            establish_ssl_session_and_set_link_up();
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
            if( timeofday_ok ) {
                if ( gettimeofday(&listen_tv_end, nullptr) != 0 ) {
                    fprintf(stderr, "gettimeofday failed in setup\n");
                    fflush(stderr);
                } else {
                    auto diff_sec = listen_tv_end.tv_sec - listen_tv_start.tv_sec;
                    auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end.tv_usec - listen_tv_start.tv_usec;
                    printf("%ld;", total_diff_in_ms);
                    //fflush(stdout);
                }
            }
#endif
        } catch(std::exception &e) {
            netif_set_link_down(own_netif_ptr);
            std::cerr << e.what() << std::endl;
            own_netif_ptr->state = nullptr;
            return ERR_IF;
        }
       
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Going to start DTLSIF thread" << std::endl;
#endif
 
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        bool timeofday_ok {true};
        struct timeval listen_tv_start {}, listen_tv_end {};
        if( gettimeofday(&listen_tv_start, nullptr) != 0 ) {
            fprintf(stderr, "gettimeofday failed in setup\n");
            fflush(stderr);
            timeofday_ok = false;
        }
#endif
        // spawn thread for input loop
        struct sys_thread *s = sys_thread_new("dtlsif_thread", RaSSLTunnelNetifOpenSSL::netif_input_loop_thread, own_netif_ptr,
                       DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        if( timeofday_ok ) {
            if ( gettimeofday(&listen_tv_end, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
            } else {
                auto diff_sec = listen_tv_end.tv_sec - listen_tv_start.tv_sec;
                auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end.tv_usec - listen_tv_start.tv_usec;
                printf("%ld;", total_diff_in_ms);
                //fflush(stdout);
            }
        }
#endif
        assert (s != nullptr);
        if (s == nullptr) {
            netif_set_link_down(own_netif_ptr);
            std::cerr << "Failed to spawn netif thread!" << std::endl;
            own_netif_ptr->state = nullptr;
            return ERR_IF;
        }
        
        // save thread id for later pthread_join()
        netif_rloop_thread_id = s->pthread;
        
        /* Graphene-SGX seems to have problems with that atm  */
        /*lwip_thread_id = pthread_self();
        
        if( pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, nullptr) != 0 ) {
            std::cerr << "Failed pthread setcancelstate" << std::endl;
        }
        
        //pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, nullptr);
        if( pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, nullptr) != 0 ) {
            std::cerr<< "Failed pthread setcanceltype" << std::endl;
        }*/
        return ERR_OK;
    }
    
    
    err_t
    RaSSLTunnelNetifOpenSSL::ip_output_trmpln(struct netif *netif, struct pbuf *p,
                                       const ip4_addr_t *ipaddr) {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "ip_output_trmpln" << std::endl;
        //std::cout.flush();
#endif
        
        // This should be impossible to happen!
        if(__glibc_unlikely(netif == nullptr || netif->state == nullptr)) {
            std::cerr << "Tunnel Output Trampoline called with empty netif or empty TunnelNetif [HOW?!]" << std::endl;
            std::cerr.flush();
            return ERR_IF;
        }
        // Should also not happen!
        if(__glibc_unlikely(p == nullptr || ipaddr == nullptr)) {
            std::cerr << "[WARNING]: pbuf or ipaddr empty in output trampoline" << std::endl;
            std::cerr.flush();
            return ERR_IF;
        }
        return ((RaSSLTunnelNetifOpenSSL *)netif->state)->ip_output_through_tunnel(netif, p, ipaddr);
    }
    
    /*-----------------------------------------------------------------------------------*/
    /*
     * ip_output_through_tunnel():
     *
     * Receives the IP packet to be send inside the pbuf (which might be chained?).
     * The IP packet will be send through the SSL tunnel to the NGW.
     *
     * @param netif The lwIP network interface which the IP packet will be sent on.
     * @param p The pbuf(s) containing the IP packet to be sent.
     * @param ipaddr The IP address of the packet destination.
     *
     * @return
     * - ERR_RTE No route to destination (no gateway to external networks),
     */
    /*-----------------------------------------------------------------------------------*/
    err_t
    RaSSLTunnelNetifOpenSSL::ip_output_through_tunnel(struct netif *netif, struct pbuf *p,
                                   const ip4_addr_t *ipaddr)
    {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "ip_output_through_tunnel" << std::endl;
        std::cout.flush();
#endif
        
#ifdef DTLSIF_DEBUG_PRINTS
        // as lwIP thread directly calls into it
        LWIP_ASSERT_CORE_LOCKED();
        
        LWIP_ASSERT("netif != NULL", netif != NULL);
        LWIP_ASSERT("p != NULL", p != NULL);
        LWIP_ASSERT("ipaddr != NULL", ipaddr != NULL);
        
        LWIP_DEBUGF(DTLSIF_DEBUG, ("[dtlsif] low_level_output()\n"));
#endif
        
#ifdef DTLSIF_DEBUG_PRINTS
        // only for debugging purposes
        std::cout << "Destination IPAddr: " << inet_ntoa({ipaddr->addr}) << std::endl;
        if (p->len >= 20) {
            std::cout << "Pbuf Src IP: " << inet_ntoa({((uint32_t *)p->payload)[3]}) << std::endl;
            std::cout << "Pbuf Dst IP: " << inet_ntoa({((uint32_t *)p->payload)[4]}) << std::endl;
        }
#endif
        
        /* Ethernet MTU: 1500; outer headers removed: - <= 40B; 1460 Bytes; we receive lwIP packet (<=1420 Bytes) + <= 40 Bytes (D)TLS */
        unsigned char send_buffer[1460];
        if (__glibc_unlikely(p->tot_len > sizeof(send_buffer))) {
            perror("dtlsif: packet too large");
            return ERR_IF;
        }

        u16_t copied = pbuf_copy_partial(p, send_buffer, p->tot_len, 0);
        if ( __glibc_unlikely(copied == 0) ) {
            perror("dtlsif: failed to copy pbuf data into send buffer");
            return ERR_IF;
        }
        
        if ( __glibc_unlikely(copied < p->tot_len) ) {
            std::cerr << "[WARNING]: could not copy all pbuf bytes" << std::endl;
            std::cerr.flush();
        }

        int ret, ssl_err;
        //u16_t len = p->tot_len;
        u16_t len = copied;
        
        // send the IP packet
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << DTLSIF_PRINT "Sending IP packet through tunnel..." << std::endl;
        //std::cout.flush();
#endif
        
        do {
            ret = SSL_write( ssl, send_buffer, len );
            ssl_err = SSL_get_error(ssl, ret);
        }
        while( ssl_err == SSL_ERROR_WANT_READ ||
              ssl_err == SSL_ERROR_WANT_WRITE );  // until done
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "ip_output_trmpln: SSL_write loop exited" << std::endl;
        //std::cout.flush();
#endif
        
        if( __glibc_unlikely(ret < 0) )
        {
            std::cerr << "[dtlsif] Failed to output packet (" << ret << ")" << std::endl;
            std::cerr.flush();
           
#ifndef RELAXED_ERROR_HANDLING
            netif_set_link_down(own_netif_ptr);
            close_tunnel_connection();
            
            // "SSL_shutdown() must not be called." ~ man page 
            if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                ssl_needs_shutdown = false;
            }
#endif
            
            return ERR_IF;
        }

#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Done. with ret: " << ret << std::endl;
        std::cout.flush();
#endif
        
        // Check if close was notified (at end to let prev. send finish)
        if(__glibc_unlikely(!spinlock__tunnel_is_open.test_and_set())) {
#ifdef DTLSIF_DEBUG_PRINTS
            std::cout << "Spinlock Close notification in netif->output" << std::endl;
            std::cout.flush();
#endif
            // refresh notification
            spinlock__tunnel_is_open.clear();
            
            // Set link down (prob. not required)
            netif_set_link_down(own_netif_ptr);
            
            // Shutdown
            //SSL_shutdown(ssl);
            
            //return ERR_IF;
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Return from ip_output_trmpln" << std::endl;
        //std::cout.flush();
#endif
        
        assert ( ret == len );
        return ERR_OK;
    }
    
    /*-----------------------------------------------------------------------------------*/
    /*
     * low_level_ip_input_from_tunnel():
     *
     * Should allocate a pbuf and transfer the bytes of the incoming
     * packet from the interface into the pbuf.
     *
     * In our case it tries to read the IP packet from the SSL tunnel.
     *
     */
    /*-----------------------------------------------------------------------------------*/
    struct pbuf *
    RaSSLTunnelNetifOpenSSL::low_level_ip_input_from_tunnel()
    {
        LWIP_DEBUGF(DTLSIF_DEBUG, ("[DTLS] low_level_ip_input_from_tunnel\n"));
        
        /* Ethernet MTU: 1500; outer headers removed: - <= 40B; 1460 Bytes; we receive lwIP packet (<=1420 Bytes) + <= 40 Bytes (D)TLS */
        unsigned char recv_buffer[1460];
        uint32_t recv_length { sizeof(recv_buffer) };
        int ret, ssl_err;
        
        // receive next IP packet via SSL connection
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Trying to read IP packet from Tunnel Connection" << std::endl;
        std::cout.flush();
#endif
        
        // Receive IP packet
        do {
            ret = SSL_read( recv_ssl, recv_buffer, recv_length );
            ssl_err = SSL_get_error(recv_ssl, ret);
        } while( ssl_err == SSL_ERROR_WANT_WRITE );
        
        // non-blocking mode (DTLS), no data available
        if (__glibc_unlikely(ssl_err == SSL_ERROR_WANT_READ)) {
            std::cerr << DTLSIF_PRINT "No data to read" << std::endl;
            return nullptr;
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Finished reading from DTLS socket with return value: " << ret << std::endl;
        std::cout.flush();
#endif
        
        if( __glibc_unlikely(ret <= 0) )
        {
            std::cerr << "[dtlsif] Failed packet read" << std::endl;
#ifndef RELAXED_ERROR_HANDLING
            switch( ssl_err )
            {
                case SSL_ERROR_ZERO_RETURN:
                    std::cerr << "[dtlsif] connection was closed gracefully" << std::endl;
                    close_tunnel_connection();
                    netifapi_netif_set_link_down(own_netif_ptr);
                    //SSL_shutdown(recv_ssl);
                    return nullptr;
                    
                default:
                    std::cerr << "[dtlsif] read error (" << ssl_err << ")" << std::endl;
                    close_tunnel_connection();
                    netifapi_netif_set_link_down(own_netif_ptr);
                    
                    /* "SSL_shutdown() must not be called." ~ man page */
                    if (ssl_err == SSL_ERROR_SSL || ssl_err == SSL_ERROR_SYSCALL) {
                        recv_needs_shutdown = false;
                    }
                    return nullptr;
            }
#else
            return nullptr;
#endif
        }
        
        /* We allocate a pbuf chain of pbufs from the pool. */
        struct pbuf *p = pbuf_alloc(PBUF_RAW, ret, PBUF_POOL);  // does it require TCPIP lock?
        if (__glibc_likely(p != nullptr)) {
            pbuf_take(p, recv_buffer, ret);
        } else {
            LWIP_DEBUGF(NETIF_DEBUG, ("low_level_ip_input_from_tunnel: could not allocate pbuf\n"));
            // TODO: how to handle that?
        }
        
        // Check if close was notified
        if(__glibc_unlikely(!spinlock__tunnel_is_open.test_and_set())) {
#ifdef DTLSIF_DEBUG_PRINTS
            std::cout << "Spinlock Close notification in input" << std::endl;
            std::cout.flush();
#endif
            
            // refresh notification
            spinlock__tunnel_is_open.clear();
            
            //SSL_shutdown(recv_ssl);
            
            // outer epoll() should detect notification in next round and do shutdown and co.
            
            // SSL_shutdown(recv_ssl);
            
            //netifapi_netif_set_link_down(own_netif_ptr);
            
            //return nullptr;
        }

        return p;
    }
    
    /*-----------------------------------------------------------------------------------*/
    /*
     * netif_input():
     *
     * This function should be called when a packet is ready to be read
     * from the interface. It uses the function low_level_ip_input_from_tunnel()
     * that should handle the actual reception of bytes from the network
     * interface.
     *
     */
    /*-----------------------------------------------------------------------------------*/
    void
    RaSSLTunnelNetifOpenSSL::netif_input()
    {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "netif_input(): trying to read from device" << std::endl;
        std::cout.flush();
#endif
        
        struct pbuf *p = low_level_ip_input_from_tunnel();
        
        if (__glibc_unlikely(p == nullptr)) {
            LWIP_DEBUGF(DTLSIF_DEBUG, ("netif_input: low_level_ip_input_from_tunnel returned nullptr\n"));
#ifdef DTLSIF_DEBUG_PRINTS
            std::cout << "low_level ip input returned nullptr (non-blocking no read? shutdown?" << std::endl;
            std::cout.flush();
#endif
            return;
        }
       
        /*
         * This currently calls tcpip_input() which just puts the IP packet into
         * a queue, from which the (separate) lwIP thread will fetch and process
         * it at some later point in time.
         */
        if (__glibc_unlikely(own_netif_ptr->input(p, own_netif_ptr) != ERR_OK)) {
            LWIP_DEBUGF(NETIF_DEBUG, ("netif_input: netif input error\n"));
            pbuf_free(p);
            p = nullptr;
        }
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "netif_input(): successfully passed received data to the stack" << std::endl;
        std::cout.flush();
#endif
    }
    
    /*-----------------------------------------------------------------------------------*/
    /*
     * linkoutput_not_supported():
     *
     * We currently only allow tunneling IP packets, not link layer frames,
     * because we have no trusted link layer stack. But this is no problem,
     * as lwIP anyway only calls the netif->output() function, and even the lwIP
     * raw sockets only work at IP packet layer, not link layer. (in contrast to
     * Linux's raw sockets which can access link layer headers, and co.)
     *
     */
    /*-----------------------------------------------------------------------------------*/
    err_t
    RaSSLTunnelNetifOpenSSL::linkoutput_not_supported(struct netif *netif, struct pbuf *p) {
        LWIP_UNUSED_ARG(netif);
        LWIP_UNUSED_ARG(p);
        LWIP_DEBUGF(DTLSIF_DEBUG, ("[DTLS] linkoutput() was called, so we ended up in linkoutput_not_supported()\n"));
        return ERR_IF;
    }
    
    void
    RaSSLTunnelNetifOpenSSL::netif_input_loop_thread(void *arg)
    {
#ifdef DTLSIF_DEBUG_PRINTS
        std::cout << "Welcome to the netif_input_loop_thread" << std::endl;
#endif
        
        // Not implemented by Graphene(-SGX), also not prctl(PR_SET_NAME)
        // pthread_setname_np(pthread_self(), "SENG|s netif");
        
        struct netif *netif;
        RaSSLTunnelNetifOpenSSL *tunnel_netif;
        netif = (struct netif *)arg;
        assert (netif != nullptr && netif->state != nullptr);
        tunnel_netif = (RaSSLTunnelNetifOpenSSL *)netif->state;
        
        int epollfd;
        epollfd = epoll_create(2); // according to manpage, the arg. is ignored
        assert (epollfd != -1);
        
        struct epoll_event ev;
        ev.events = EPOLLIN;
        
        int tun_fd = SSL_get_fd(tunnel_netif->recv_ssl);
        if (tun_fd < 0) {
            throw std::runtime_error("Failed to get recv tunnel fd");
        }
        
        ev.data.fd = tun_fd;
        auto ret = epoll_ctl(epollfd, EPOLL_CTL_ADD, tun_fd, &ev);
        if (ret == -1) throw std::runtime_error("epoll_ctl() failed ~ recv tunnel");
        
        // For close notification
        auto wait_fd = tunnel_netif->notification_sockets[WAIT_FOR_NOTIFY];
        struct epoll_event close_ev;
        close_ev.events = EPOLLIN;
        close_ev.data.fd = wait_fd;
        ret = epoll_ctl(epollfd, EPOLL_CTL_ADD,
                        wait_fd,
                        &close_ev);
        if (ret == -1) throw std::runtime_error("epoll_ctl() failed ~ socketpair");
        
        int nfds;
        /* 1st loop */
        for (;;) {
            struct epoll_event events[2];
            nfds = epoll_wait(epollfd, events, 2, -1);
            
            // Check for interrupt or error
            if (__glibc_unlikely(nfds == -1)) {
                if (errno == EINTR) {
#ifdef DTLSIF_DEBUG_PRINTS
                    std::cerr << DTLSIF_PRINT "epoll() returned -1 with EINTR!" << std::endl;
                    std::cerr.flush();
#endif
                    continue;
                }
                // error, so close!
                tunnel_netif->close_tunnel_connection();
                netifapi_netif_set_link_down(tunnel_netif->own_netif_ptr);
                //SSL_shutdown(tunnel_netif->recv_ssl);
                break;
            }
            
            // On socket close
            if (__glibc_unlikely(nfds == 0)) {
#ifdef DTLSIF_DEBUG_PRINTS
                std::cerr << DTLSIF_PRINT "All sockets seem to be closed!" << std::endl;
                std::cerr.flush();
#endif

#ifndef RELAXED_ERROR_HANDLING
                tunnel_netif->close_tunnel_connection();
                netifapi_netif_set_link_down(tunnel_netif->own_netif_ptr);
                //SSL_shutdown(tunnel_netif->recv_ssl);
                break;
#else
                tunnel_netif->netif_input(); // need o_nonblock
                continue;
#endif
            }
            
            // Check if close notification!
            if (__glibc_unlikely( nfds == 2 || ( nfds == 1 && (events[0].data.fd == wait_fd) ) ) ) {
            
            // Check if only close notification
#ifdef DTLSIF_DEBUG_PRINTS
                std::cerr << DTLSIF_PRINT "Close notification!" << std::endl;
                std::cerr.flush();
#endif
                
                char buf[1];
                // try to read that we don't trigger it again directly
                if (read(wait_fd, buf, sizeof(buf)) != 1) {
                    std::cerr << DTLSIF_PRINT "Failed to empty socketpair trigger" << std::endl;
                    std::cerr.flush();
                }
                
                break;
            }
            
            assert (nfds == 1);
            tunnel_netif->netif_input();
        }
        

        
        
        /* Check if graceful shutdown, i.e. NOT YET cleared flag */
        if (tunnel_netif->spinlock__tunnel_is_open.test_and_set()) {
#ifdef DTLSIF_DEBUG_PRINTS
            std::cout << "Entering the graceful loop" << std::endl;
#endif
            
            /* Graceful Shutdown loop */
#ifdef RELAXED_ERROR_HANDLING
            int timeout_counter = 0;
#endif
            for (;;) {
                struct epoll_event events[2];
                // seems to be different timing than in manpage?! micro vs milli?!
                // because 10000000 seems to be 10seconds
                // 5000000 ~ 5sec
                // but 5000 instant
                nfds = epoll_wait(epollfd, events, 2, 5000); // 2 sec timeout; ~5ms
                
                // Check for interrupt or error
                if (__glibc_unlikely(nfds == -1)) {
                    if (errno == EINTR) {
                        continue;
                    }
                    tunnel_netif->close_tunnel_connection();
                    netifapi_netif_set_link_down(tunnel_netif->own_netif_ptr);
                    //SSL_shutdown(tunnel_netif->recv_ssl);
                    break;
                }
                
                // Timeout
                if ( nfds == 0 ) {
#ifdef RELAXED_ERROR_HANDLING
                    timeout_counter++;
                    if (timeout_counter < 2) continue;
#endif

#ifdef DTLSIF_DEBUG_PRINTS
                    std::cout << DTLSIF_PRINT "Timeout, so now finally closed" << std::endl;
                    std::cout.flush();
#endif
                    tunnel_netif->close_tunnel_connection();
                    // Correct, right?
                    netifapi_netif_set_link_down(tunnel_netif->own_netif_ptr);
                    //SSL_shutdown(tunnel_netif->recv_ssl);
                    break;
                }
                
                // Check if close notification! (that basically means an error has occured, I guess)
                if (__glibc_unlikely( nfds == 2 || ( nfds == 1 && (events[0].data.fd == wait_fd) ) ) ) {
                    
                    // Saftey Check
                    if (tunnel_netif->spinlock__tunnel_is_open.test_and_set()) {
                        std::cerr << DTLSIF_PRINT "[ERROR] Notified in graceful loop, but flag not yet cleared!!" << std::endl;
                    } else {
                    }
                    //netifapi_netif_set_link_down(tunnel_netif->own_netif_ptr);
                    tunnel_netif->spinlock__tunnel_is_open.clear();
                    // TODO: prob. error, right? so probl. should not/MUST NOT call : SSL_shutdown(tunnel_netif->recv_ssl);
                    break;
                }
                
                assert (nfds == 1);
                tunnel_netif->netif_input();
            }
            
        }
        
        // clear again
        tunnel_netif->spinlock__tunnel_is_open.clear();
        
        // DON'T DO THAT !; seems it made pthread_wait() hang
        //tunnel_netif->netif_rloop_thread_id = -1;
        
#ifdef DTLSIF_DEBUG_PRINTS
        std::cerr << DTLSIF_PRINT "EXITING netif_input_loop_thread" << std::endl;
        std::cerr.flush();
#endif
    }
}
