#ifndef SENG_TUNNELTOENCLAVE_OPENSSL_HPP
#define SENG_TUNNELTOENCLAVE_OPENSSL_HPP

#include "SSLEngine_OpenSSL.hpp"
#include "PacketForwarder_adapted.hpp"
#include "EncIdxBase.hpp"

#include <memory>
#include <vector>

#include <sgx_quote.h>

#include <netinet/in.h>

#include <sys/types.h> // ssize_t

#include <uv.h>


namespace seng {
    struct TunnelToEnclaveOpenSSL {
        TunnelToEnclaveOpenSSL(SSL *, std::shared_ptr<PacketForwarder> &,
                        std::shared_ptr<EnclaveIndexBase> &, uv_udp_t *);
        ~TunnelToEnclaveOpenSSL();
        
        union {
            //uv_tcp_t *tcp_sock;
            uv_udp_t *udp_sock;
        } socket_to_enclave;
        
        //! 1st DTLS tunnel; For receiving packets from Enclave
        SSL *ssl;
        //! 2nd DTLS tunnel; For sending packets to Enclave
        SSL *send_ssl;
        
        std::shared_ptr<PacketForwarder> ip_pckt_fwder_sp;
        std::shared_ptr<EnclaveIndexBase> enclave_idx_sp;
        
        // TODO: timeout handler/handling?
        
        sgx_quote_t quote;
        
        in_addr_t internal_enclave_ip;
        in_addr_t untrusted_tunnel_host_ip;
        
        void extract_tunnel_host_ip(uv_handle_t *);
        
        //! Try to perform SSL handshake, extract SGX quote and perform access check
        void establish_ssl_session();
        void show_certificate_verification_results(SSL *ssl_obj);
        //! Extract SGX Quote from Certificate (of 1st Tunnel)
        void extract_sgx_quote_from_certificate();
        bool check_if_enclave_has_network_access();
        //! Check that SGX Quote contained in Certificate in 2nd Tunnel matches that of 1st
        bool check_for_consistent_quotes();
        
        void assign_internal_ip(in_addr_t, in_addr_t, in_addr_t);
        
        void start_event_listeners();
        
        //! UV read callback
        static void trmpln_dtls_ip_pckt_recv(uv_udp_t *, ssize_t, const uv_buf_t *,
                                             const struct sockaddr *, unsigned);
        void dtls_recv_ip_pckt_from_enclave();
        void handle_ip_pckt_from_enclave(std::unique_ptr<unsigned char[]>, int);
        
        void tunnel_reply_to_enclave(std::unique_ptr<unsigned char[]>, ssize_t);
        
        bool closed;
        void close_tunnel_connection(); // TODO: might allow loss-less reconnections later
    };
}

#endif /* SENG_TUNNELTOENCLAVE_OPENSSL_HPP */
