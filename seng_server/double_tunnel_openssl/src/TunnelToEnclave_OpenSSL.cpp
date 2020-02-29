#include "TunnelToEnclave_OpenSSL.hpp"

#include "OpenSSLUVCallbacks.hpp"

#include <string>
#include <iostream>
#include <stdexcept>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <cassert>
#include <cstring>

#include <arpa/inet.h>

#include <unistd.h>

#include <linux/ip.h> // struct iphdr

// SGX-RA-TLS headers
extern "C" {
#include <ra.h>
#include <ra-challenger.h>
}

#include "seng.pb.h"

//#define DEBUG_TTE


namespace seng {
    TunnelToEnclaveOpenSSL::TunnelToEnclaveOpenSSL(SSL *ssl, std::shared_ptr<PacketForwarder> &pcktfwd,
                                     std::shared_ptr<EnclaveIndexBase> &enc_idx, uv_udp_t *conn_socket)
    : ssl(ssl), send_ssl(nullptr), ip_pckt_fwder_sp(pcktfwd),
    enclave_idx_sp(enc_idx), quote({}), internal_enclave_ip(), closed(false) {
        assert(ssl != nullptr && conn_socket != nullptr);
        socket_to_enclave.udp_sock = conn_socket;
        extract_tunnel_host_ip((uv_handle_t *) conn_socket);
    }
    TunnelToEnclaveOpenSSL::~TunnelToEnclaveOpenSSL() {
        if (!closed) close_tunnel_connection();
        assert(socket_to_enclave.udp_sock == nullptr);
    }
    
    void TunnelToEnclaveOpenSSL::extract_tunnel_host_ip(uv_handle_t *conn_hndl) {
        uv_os_fd_t sockfd;
        int ret = uv_fileno(conn_hndl, &sockfd);
        assert(ret == 0);
        
        struct sockaddr_in host_addr;
        socklen_t hostaddr_len { sizeof(host_addr) };
        ret = getpeername(sockfd, (struct sockaddr *)&host_addr, &hostaddr_len);
        assert(ret == 0);
        
        untrusted_tunnel_host_ip = host_addr.sin_addr.s_addr;
    }
    
    void TunnelToEnclaveOpenSSL::establish_ssl_session() {
#ifdef DEBUG_TTE
        std::cout << "Trying to perform SSL handshake" << std::endl;
#endif
        
        // SSL handshake for Receive Tunnel (#1)
        int ret, ssl_err;
        if (SSL_accept(ssl) <= 0) {
            ssl_err = SSL_get_error(ssl, ret);
#ifdef DEBUG_TTE
            std::cout << "Something went wrong during SSL handshake!" << std::endl;
#endif
            throw std::runtime_error(std::string("SSL handshake with new Enclave "
                                                 "failed with return value: "
                                                 + std::to_string(ret) +
                                                 " and error code: "
                                                 + std::to_string(ssl_err)));
        }
        
#ifdef DEBUG_TTE
        std::cout << "Finished SSL handshake" << std::endl;
#endif
        
#ifdef DEBUG_TTE
        // debug print certificate state;
        // Doesn't make much sense at the moment bcs. self-signed cert. will show "failed"
        //show_certificate_verification_results(ssl);
#endif
        
        // extract SGX quote/report
        extract_sgx_quote_from_certificate();
        
        // check access based on SGX quote/report
        if (! check_if_enclave_has_network_access()) {
            throw std::runtime_error("The connected enclave does NOT have any network access permissions");
        }
        
        /* Prepare 2nd DTLS Tunnel connection! */
#ifdef DEBUG_TTE
        std::cout << "Create 2nd DTLS Socket" << std::endl;
#endif
        int response_tun = socket(AF_INET, SOCK_DGRAM, 0);
        if (response_tun < 0) {
            throw std::runtime_error("Failed to create 2nd UDP Socket");
        }
        
        int one = 1;
        setsockopt(response_tun, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        
        // set non-blocking later! (after handshake!)

        struct sockaddr_in add {
            .sin_family = AF_INET,
            .sin_port = htons(4711),
            .sin_addr = {0},
        };
        inet_aton("127.0.0.1", &add.sin_addr);
        if(bind(response_tun, (struct sockaddr *)&add, sizeof(add)) < 0) {
            close(response_tun);
            throw std::runtime_error("bind error");
        }
        
        /* TODO: would be cool if we could connect() to IP of client here,
            because this will probably cause error on multiple parallel connection attempts! */
        
        // Create BIO
        BIO *response_bio = BIO_new_dgram(response_tun, BIO_CLOSE);
        if (response_bio == nullptr) {
            close(response_tun);
            throw std::runtime_error("bio error");
        }
        
        // Create SSL context
        send_ssl = SSL_new(SSL_get_SSL_CTX(ssl));
        if (send_ssl == nullptr) {
            BIO_free_all(response_bio);
            throw std::runtime_error("ssl error");
        }
        // Set short timeout
        struct timeval timeout {
            .tv_sec = 5,
            .tv_usec = 0
        };
        BIO_ctrl(response_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
        SSL_set_bio(send_ssl, response_bio, response_bio);
        SSL_set_options(send_ssl, SSL_OP_NO_QUERY_MTU);
        SSL_set_mtu(send_ssl, ip_pckt_fwder_sp->tunnel_mtu);
        SSL_set_options(send_ssl, SSL_OP_COOKIE_EXCHANGE);
#ifdef DEBUG_TTE
        std::cout << "2nd Created" << std::endl;
#endif
    }

    void TunnelToEnclaveOpenSSL::show_certificate_verification_results(SSL *ssl_obj) {
        uint32_t flags;
        std::cout << "Results of client certificate verification:" << std::endl;
        // TODO: prob. would want to cancel connection if verification has failed!
        if(SSL_get_verify_result(ssl_obj) == X509_V_OK) {
            std::cout << " ok" << std::endl;
        } else {
            std::cout << " failed" << std::endl;
        }
    }
    
    void TunnelToEnclaveOpenSSL::extract_sgx_quote_from_certificate() {
        // Get Client certificate from 1st Tunnel!
        X509 *cli_cert = SSL_get_peer_certificate(ssl);
        if (cli_cert == nullptr) throw std::runtime_error("No client certificate! (1st tunnel)");
        
        int der_len = i2d_X509(cli_cert, NULL);
        if (der_len <= 0) throw std::runtime_error("Invalid Client certificate length!");
        //assert(der_len > 0);
        
        unsigned char der[der_len];
        unsigned char *p = der;
        i2d_X509(cli_cert, &p);
        
#ifdef DEBUG_TTE
        std::cout << "Trying to extract SGX Quote from Certificate" << std::endl;
#endif
        
        get_quote_from_cert(der, der_len, &quote);
        
#ifdef DEBUG_TTE
        std::cout << "Extracted." << std::endl;
#endif
    }
    
    bool TunnelToEnclaveOpenSSL::check_for_consistent_quotes() {
        // Get Client certificate from 2nd Tunnel!
        X509 *cli_cert = SSL_get_peer_certificate(send_ssl);
        if (cli_cert == nullptr) throw std::runtime_error("No client certificate! (2nd tunnel)");
        
        int der_len = i2d_X509(cli_cert, NULL);
        if (der_len <= 0) throw std::runtime_error("Invalid Client certificate length!");
        //assert(der_len > 0);
        
        sgx_quote_t second_quote {0};
        
        unsigned char der[der_len];
        unsigned char *p = der;
        i2d_X509(cli_cert, &p);
      
#ifdef DEBUG_TTE
        std::cout << "Trying to extract SGX Quote from 2nd Certificate" << std::endl;
#endif
        
        get_quote_from_cert(der, der_len, &second_quote);
        
#ifdef DEBUG_TTE
        std::cout << "Extracted." << std::endl;
#endif
      
#ifdef DEBUG_TTE
        std::cout << "Checking that it matches the first one!" << std::endl;
#endif
        if( std::memcmp(&quote, &second_quote, sizeof(sgx_quote_t)) != 0 ||
            quote.signature_len != second_quote.signature_len ||
            std::memcmp(quote.signature, second_quote.signature, quote.signature_len) != 0) {
            return false;
        }
#ifdef DEBUG_TTE
        std::cout << "Quote + Signature seem to match between the 2 tunnels!" << std::endl;
#endif
        
        return true;
    }
    
    //! Extract and check values of IAS Report and determine network access
    bool TunnelToEnclaveOpenSSL::check_if_enclave_has_network_access() {
        sgx_report_body_t *body = &quote.report_body;
        assert (body != nullptr);

//#ifdef DEBUG_TTE
        std::cout << "Certificate's SGX information:" << std::endl;
        std::cout << "  . MRENCLAVE = ";
        for (int i=0; i < SGX_HASH_SIZE; ++i) {
            printf("%02x", body->mr_enclave.m[i]);
        }
        std::cout << std::endl;
        
        std::cout << "  . MRSIGNER  = ";
        for (int i = 0; i < SGX_HASH_SIZE; ++i) {
            printf("%02x", body->mr_signer.m[i]);
        }
        std::cout << std::endl;
//#endif
        
        return enclave_idx_sp->is_whitelisted_app(body);
        // TODO: perform checks on report
        //return true;
    }
    
    void TunnelToEnclaveOpenSSL::start_event_listeners() {
        uv_udp_recv_start(socket_to_enclave.udp_sock,
                          OsslUVCbs::not_touch_read_buffer,
                          TunnelToEnclaveOpenSSL::trmpln_dtls_ip_pckt_recv);
    }
    
    void TunnelToEnclaveOpenSSL::trmpln_dtls_ip_pckt_recv(uv_udp_t *client, ssize_t nread, const uv_buf_t* buf, const struct sockaddr* addr, unsigned flags) {
#ifdef DEBUG_TTE
        std::cout << "trmpln_dtls_ip_pckt_recv called" << std::endl;
        std::cout.flush();
#endif
        // as we use ignoring alloc CB
        assert(nread == UV_ENOBUFS && addr == nullptr && flags == 0);
        
        assert(uv_is_closing((uv_handle_t *) client) == 0);
        
        assert(client->data != nullptr);
        ((TunnelToEnclaveOpenSSL *)client->data)->dtls_recv_ip_pckt_from_enclave();
    }
    void TunnelToEnclaveOpenSSL::dtls_recv_ip_pckt_from_enclave() {
#ifdef DEBUG_TTE
        std::cout << "dtls_recv_ip_pckt_from_enclave()" << std::endl;
#endif

        if (closed) {
            std::cerr << "dtls_recv_ip_pckt_from_enclave: EARLY RETURN bcs. CLOSED" << std::endl;
            return;
        }
        assert(!closed); // has fired multiple times in the past!
       
        // [over Ethernet, no jumbos] for TLS tunnel: <=1420B, for DTLS tunnel: <=1432B (with minimal headers)
        int ret, ssl_err, len = 1432;
        auto buf_up = std::make_unique<unsigned char[]>(len);
        
        do {
            ret = SSL_read(ssl, buf_up.get(), len);
            ssl_err = SSL_get_error(ssl, ret);
        }
        while( ssl_err == SSL_ERROR_WANT_WRITE );
        
        // no datagram currently available / being processed
        if(ssl_err == SSL_ERROR_WANT_READ) {
            std::cerr << "DTLS: nothing to read" << std::endl;
            std::cerr.flush();
            return;
        }
        
        // some kind of error / shutdown
        if(ret <= 0) return close_tunnel_connection();
        
        len = ret;
        handle_ip_pckt_from_enclave(std::move(buf_up), len);
    }
    
    void TunnelToEnclaveOpenSSL::handle_ip_pckt_from_enclave(std::unique_ptr<unsigned char[]> ip_pckt_up,
                                                      int len) {
        // Security Check: only allow sender IP that we assigned this Enclave
        auto ip_hdr_ptr = (struct iphdr *) ip_pckt_up.get();
        if(ip_hdr_ptr->saddr != internal_enclave_ip) {
            std::cerr << "[ALERT] Received IP packet from Enclave with srcIP not"
            << " matching the internally assigned IP!";
            std::cerr << "(expected: " << inet_ntoa({internal_enclave_ip})
            << "/" << internal_enclave_ip;
            // NOTE: avoid using inet_ntoa() twice in same statement, bcs. of static internal buffer
            std::cerr << ", observed: " << inet_ntoa({ip_hdr_ptr->saddr})
            << "/" << ip_hdr_ptr->saddr << ")" << std::endl;
            return; // drop
        }
        
        auto ret = ip_pckt_fwder_sp->send_ip_packet(std::move(ip_pckt_up), len);
        if (ret < 0) {
            if (errno == EAGAIN) {
                std::cerr << "Writing attempt on TUN returned EAGAIN (non-blocking mode) which is strange" << std::endl;
            }
            throw std::runtime_error(std::string("Failed to Forward IP Packet from Enclave")
                                              + std::strerror(errno));
        }
        if( ret != len ) throw std::runtime_error("Failed to forward full IP packet through tunnel"); // TODO: is a write loop required for this interface?
    }
    
    void TunnelToEnclaveOpenSSL::close_tunnel_connection() {
        //assert (!closed);
        if (closed) {
            std::cout << "[INFO] IDLE -- close_tunnel_connection() called while already closed" << std::endl;
            return;
        }
        if (ssl == nullptr) {
            // SHOULD NOT HAPPEN
            std::cout << "[WARNING/ERROR] -- closed_tunnel_connection() called while ssl == nullptr" << std::endl;
            return;
        }
        
//#ifdef DEBUG_TTE
        std::cout << "Closing TunnelToEnclave";
        if (internal_enclave_ip) std::cout << ": " << inet_ntoa({internal_enclave_ip});
        std::cout << std::endl;
        std::cout.flush();
//#endif
        
        int ret, ssl_err;
        struct timeval timeout_short {
            .tv_sec = 3,
            .tv_usec = 0
        };
        
        /* Receive Tunnel */
        assert(ssl != nullptr);
        
        // for faster timeouts
        BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_short);
        
        // graceful close notification
        // TODO: might want to add loop later on; but note that timeout + non-blocking doesn't make sense probbaly
        ret = SSL_shutdown(ssl);
        
        // TODO: wait for reply? (prob. NO)

        // disable receive listener
        ret = uv_udp_recv_stop(socket_to_enclave.udp_sock);
        assert( ret == 0 );
        uv_close((uv_handle_t *) socket_to_enclave.udp_sock, OsslUVCbs::free_handle_on_close);
        socket_to_enclave.udp_sock = nullptr;
   
        // free
        SSL_free(ssl);
        ssl = nullptr;
        
        /* Send Tunnel (if exists) */
        if (send_ssl != nullptr) {
            BIO_ctrl(SSL_get_rbio(send_ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_short);
            // TODO: add loop; but timeout + non-blocking probably does not make sense
                ret = SSL_shutdown(send_ssl);
            SSL_free(send_ssl);
            send_ssl = nullptr;
        }
        
        // could add check if(internal_enclave_ip != 0) for case of early close
        if (internal_enclave_ip) enclave_idx_sp->mark_enclave_tunnel_closed(internal_enclave_ip);
        
        closed = true;
        
        //#ifdef DEBUG_TTE
        std::cout << "TunnelToEnclave";
        if (internal_enclave_ip) std::cout << ": " << inet_ntoa({internal_enclave_ip});
        std::cout << " now closed." << std::endl;
        std::cout.flush();
        //#endif
    }
    
    void TunnelToEnclaveOpenSSL::assign_internal_ip(in_addr_t internal_ip,
                                             in_addr_t netmask,
                                             in_addr_t gateway) {
        assert (!closed);
        
        std::cout << "Assigning internal IP: " << inet_ntoa({internal_ip})
        << " to Enclave" << std::endl;
        
        // Craft IPAssignment Protobuf message
        seng_proto::IpAssignment msg;
        msg.set_ip(internal_ip);
        msg.set_netmask(netmask);
        msg.set_gw_ip(gateway);
        
        // serialize the message into a string buffer
        std::string msg_data;
        bool ret_bool;
        ret_bool =  msg.SerializeToString(&msg_data);
        assert( ret_bool );

        // TODO: proper ACK and lockstep mechanism with retransmissions and timeouts (as in DTLS handshake) is not implemented yet!
        int retries {2};
        while (true) {
            retries--;
#ifdef DEBUG_TTE
            std::cout << "Sending IP to Enclave" << std::endl;
#endif
            
            // blocking, so will timeout after 3 sec; but write failure would be weird
            if ( SSL_write(ssl, (const unsigned char *)msg_data.data(),
                                   msg_data.size()) != msg_data.size() ) {
                throw std::runtime_error("Failed to send Internal IP to Enclave at once, but write loop NOT IMPLEMENTED, yet");
            }
            
            // TODO: DTLS is unreliable, so need Timeout-ACK mechanism
            int ret, ssl_err;
            unsigned char buf[20];
#ifdef DEBUG_TTE
            std::cout << "Try to receive IP ACK from Enclave" << std::endl;
#endif
            ret = SSL_read(ssl, buf, sizeof(buf));
            ssl_err = SSL_get_error(ssl, ret);
            
            if (ret <= 0 && ssl_err != SSL_ERROR_WANT_READ) {
                close_tunnel_connection();
                throw std::logic_error("And error has occurred during receive");
            }
            
            seng_proto::IpAssignACK ack_msg;
            if (ack_msg.ParseFromArray(buf, ret)) {
#ifdef DEBUG_TTE
                std::cout << "Received IP Assign ACK" << std::endl;
#endif
                break;
            } else {
                std::cerr << "Failed parsing IpAssignACK message" << std::endl;
                std::cerr << "Received in read: " << ret << std::endl;
                std::cerr << "Max buf size was: " << sizeof(buf) << std::endl;
            }
            
            if(retries == 0) {
                close_tunnel_connection();
                throw std::runtime_error("Failed to assign interal IP to Enclave; shutting down the tunnel");
            }
        }

        // save assigned internal IP for reply packet dispatching
        internal_enclave_ip = internal_ip;
#ifdef DEBUG_TTE
        std::cout << "Done." << std::endl;
#endif
        
        
        
        
        
        /* Try to accept 2nd DTLS connection */
#ifdef DEBUG_TTE
        std::cout << "Now trying to accept 2nd DTLS tunnel connection" << std::endl;
        std::cout.flush();
#endif
        
        struct sockaddr_in cli_addr {};
        int ret = DTLSv1_listen(send_ssl, &cli_addr);
        if (ret <= 0) throw std::runtime_error("Failed to accept 2nd DTLS connection");
        
        // Check: Quote is same + IP is same!
        // TODO: check quote
        // check IP
        if (cli_addr.sin_family != AF_INET ||
            cli_addr.sin_addr.s_addr != untrusted_tunnel_host_ip) {
            throw std::runtime_error("Wrong Client IP for 2nd DTLS connection");
        }

#ifdef DEBUG_TTE
        std::cout << "Incoming 2nd DTLS tunnel connection" << std::endl;
        std::cout.flush();
#endif
        
        // get stuff
        auto bio = SSL_get_rbio(send_ssl);
        if (bio == nullptr) throw std::runtime_error("Failed to get BIO of 2nd DTLS tunnel");
        
        int fd;
        BIO_get_fd(bio, &fd);
        if (fd <= 0) throw std::runtime_error("Failed to get socket FD of 2nd DTLS tunnel");
        
        //int zero = 0;
      //  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof(zero));
#ifdef SO_REUSEPORT
        int one = 1;
        // NOTE: Linux Kernel will keep delivering to UDP Socket that has received the first packet from the sender!
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
        
        // Connect the Socket to the Client address!
        if(connect(fd, (struct sockaddr *)&cli_addr, sizeof(struct sockaddr_in)) < 0) {
            throw std::runtime_error("Failed to connect 2nd DTLS tunnel to client IP");
        }
        
        // set connected
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &cli_addr);
        
#ifdef DEBUG_TTE
        std::cout << "Trying to finish 2nd DTLS tunnel handshake" << std::endl;
        std::cout.flush();
#endif
        
        // try to finish the handshake
        int ssl_err;
        if (SSL_accept(send_ssl) <= 0) {
            ssl_err = SSL_get_error(send_ssl, ret);
#ifdef DEBUG_TTE
                std::cout << "Something went wrong during SSL handshake!" << std::endl;
#endif
            throw std::runtime_error(std::string("SSL handshake with new Enclave "
                                                 "failed with return value: "
                                                 + std::to_string(ret) +
                                                 " and error code: "
                                                 + std::to_string(ssl_err)));
        }
        
        // set non-blocking now!
        BIO_set_nbio(bio, 1);
        
        // Set and activate longer timeouts now
        struct timeval timeout_long {
            .tv_sec = 120,
            .tv_usec = 0
        };
        BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_long);

#ifdef DEBUG_TTE
        std::cout << "Done with accepting 2 DTLS connection!" << std::endl;
        std::cout.flush();
#endif
        
        if (!check_for_consistent_quotes()) {
            throw std::runtime_error("The SGX Quotes/Signatures of the 2 Tunnel do not seem to match!");
        }
    }
    
    void TunnelToEnclaveOpenSSL::tunnel_reply_to_enclave(std::unique_ptr<unsigned char[]> ip_pckt_up,
                                                  ssize_t pckt_len) {
        assert (pckt_len > 0);
        int ret, ssl_err;
        
        do {
            ret = SSL_write(send_ssl, ip_pckt_up.get(), pckt_len);
            ssl_err = SSL_get_error(send_ssl, ret);
        }
        while ( ssl_err == SSL_ERROR_WANT_WRITE || ssl_err == SSL_ERROR_WANT_READ );
        
        // some kind of error / shutdown
        if(ret < 0) return close_tunnel_connection();
        
        assert (ret != 0);
    }
}
