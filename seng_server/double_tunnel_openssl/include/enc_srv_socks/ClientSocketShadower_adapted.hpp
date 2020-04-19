#ifndef SENG_CLISOCK_SHADOWER_HPP
#define SENG_CLISOCK_SHADOWER_HPP

#include <memory>
#include <atomic>
#include <limits>
#include <utility>

#include <vector>
#include <experimental/optional>
#include <string>

#include <mbedtls/ssl.h>
#include <mbedtls/net.h>
//#include <mbedtls/net_sockets.h>

#include "EnclaveIndex_adapted.hpp"
#include "SSLEngine.hpp"

#include "seng.pb.h"

using namespace std::experimental;


namespace seng {
    enum class SessionState {
        WAIT_FOR_CONNECTION = 0,
        ESTABLISH_SESSION,
        ACTIVE_SESSION,
        
        WAIT_FOR_REQ_MSG,
        CHECK_VALID_REQUEST,
        
        CLOSE_NOTIFY__START_PROCESSING,
        CLOSE_NOTIFY__CHECK_WHETHER_WAS_SHADOWED,
        CLOSE_NOTIFY__WAS_NOT_SHADOWED,
        CLOSE_NOTIFY__CONNECT_TO_CLISB,
        //CLOSE_NOTIFY__ESTABLISH_CLISB_SESSION,
        CLOSE_NOTIFY__SEND_CLOSE_REQ_TO_CLISB,
        CLOSE_NOTIFY__REMOVE_SHADOW_RULE,
        CLOSE_NOTIFY__SUCCESS,
        CLOSE_NOTIFY__FAILED,

        SHADOW_REQ__START_PROCESSING,
        SHADOW_REQ__CHECK_WHETHER_ALREADY_SHADOWED,
        SHADOW_REQ__SEND_ALREADY_SHADOWED_TO_ENC,
        SHADOW_REQ__CONNECT_TO_CLISB,
        //SHADOW_REQ__ESTABLISH_CLISB_SESSION,
        SHADOW_REQ__SEND_BLOCK_REQ_TO_CLISB,
        SHADOW_REQ__WAIT_FOR_CLISB_REPLY,
        SHADOW_REQ__SEND_DENIED_TO_ENC,
        SHADOW_REQ__PROBE_RULES_INTEGRATION,
        SHADOW_REQ__ABORT_DUE_TO_INTEGRATION_ERROR,
        SHADOW_REQ__SEND_GRANTED_TO_ENC,
        SHADOW_REQ__WAIT_FOR_CONFIRM_MSG_BY_ENC,
        SHADOW_REQ__FWD_CONFIRM_TO_CLISB,
        SHADOW_REQ__COMMIT_SHADOW_RULES,
        SHADOW_REQ__SUCCESS,
        SHADOW_REQ__FAILED,
        
        FINISHING_SESSION,
    };
    
    class CliSockShadower {
    public:
        CliSockShadower(std::shared_ptr<EnclaveIndexBase> &);
        ~CliSockShadower();
 
        void run_cmd_server();
        void send_stop_signal();
    private:
        std::shared_ptr<EnclaveIndexBase> enclave_idx_sp;
        SSLEngine ssl_engine;
        
        int srv_socket;
        
        std::atomic_bool atomic_stop_server;
        
        void setup_welcome_socket();
        void start_listening();
        void handle_connection(int enc_sock, struct sockaddr_in enc_addr, SessionState &session_state);
        
        void handle_shadow_request(int enc_sock, struct sockaddr_in enclave_addr,
                                   SessionState &session_state, std::vector<unsigned char> &,
                                   const seng_proto::ShadowSrvMsg_RequestCliSockShadowing &shadow_msg);
        void handle_close_notification(int enc_sock, struct sockaddr_in enclave_addr,
                                       SessionState &session_state, std::vector<unsigned char> &,
                                       const seng_proto::ShadowSrvMsg_NotifyAboutClose &close_msg);
        
        optional<
            std::pair<
                std::unique_ptr<mbedtls_net_context>,
                std::unique_ptr<mbedtls_ssl_context>
            >
        > connect_to_client_sock_blocker(in_addr_t client_ip);
        
        static void shutdown_connection_to_clisb(mbedtls_net_context *, mbedtls_ssl_context *);
        
        //! Receive next protobuf message from sockfd; return length, and put data into the given buf; std::nullopt on failure;
        static optional<uint32_t> receive_protobuf_message(int sockfd, std::vector<unsigned char> &buf);
        static bool send_protobuf_message(int sockfd, std::string &msg);
        
        static optional<uint32_t> ssl_receive_protomsg(mbedtls_ssl_context *ssl_ctx, std::vector<unsigned char> &buf);
        static bool ssl_send_protomsg(mbedtls_ssl_context *ssl_ctx, std::string &msg);
        
        static bool is_supported_protocol(uint8_t proto);
        static bool is_in_port_range(in_port_t port);
    };
}

#endif /* SENG_CLISOCK_SHADOWER_HPP */
