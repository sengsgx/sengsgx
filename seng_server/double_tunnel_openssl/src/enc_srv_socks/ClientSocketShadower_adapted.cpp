#include "enc_srv_socks/ClientSocketShadower_adapted.hpp"

#include <iostream>
#include <stdexcept>

#include <poll.h>

#include <cassert>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <mbedtls/certs.h>

//#define DEBUG_SHADOWER


namespace seng {
    CliSockShadower::CliSockShadower(std::shared_ptr<EnclaveIndexBase> &enc_idx_sp) :
    enclave_idx_sp(enc_idx_sp), ssl_engine(SSLType::TLS), srv_socket(-1), atomic_stop_server(false) {
        ssl_engine.configure((const unsigned char *) mbedtls_test_cli_crt, mbedtls_test_cli_crt_len,
                             (const unsigned char*) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len,
                             (const unsigned char *) mbedtls_test_cli_key, mbedtls_test_cli_key_len,
                             nullptr, 0, nullptr,
                             false); // client
    }
    
    CliSockShadower::~CliSockShadower() {
        if(srv_socket>=0) close(srv_socket);
    }
    
    void CliSockShadower::run_cmd_server() {
        std::cout << "Welcome to the CliSockShadower Service" << std::endl;
        setup_welcome_socket();
        start_listening();
    }
    
    void CliSockShadower::setup_welcome_socket() {
        // Create TCP Socket
        int tmp_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (tmp_sock < 0) {
            perror(nullptr);
            throw std::runtime_error("Failed to create Shadower Server socket");
        }
        
        int enable { 1 };
        if (setsockopt(tmp_sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror(nullptr);
            close(tmp_sock);
            throw std::runtime_error("Failed to set SO_REUSEADDR flag for Shaodwer Server Socket");
        }

        // Bind to tunFA IP
        struct sockaddr_in tun_addr {
            .sin_family = AF_INET,
            .sin_port = htons(2409),
        };
        //TODO: dynamically query the virtual interface IP
        int ret = inet_aton("192.168.28.1", &tun_addr.sin_addr);
        assert(ret != 0);
        if (bind(tmp_sock, (struct sockaddr *)&tun_addr, sizeof(tun_addr)) < 0) {
            perror(nullptr);
            close(tmp_sock);
            throw std::runtime_error("Failed to bind Shadow Server socket to tunFA IP");
        }
        
        // Safe set-up socket
        srv_socket = tmp_sock;
    }
    
    void CliSockShadower::start_listening() {
        if (listen(srv_socket, 5) < 0) {
            perror(nullptr);
            throw std::runtime_error("Failed to switch Shadow Server socket into listen mode");
        }
        
        struct sockaddr_in cli_addr {};
        socklen_t cliaddr_len {};
        
        struct pollfd pfd {
            .fd = srv_socket,
            .events = POLLIN,
            .revents = 0,
        };
        
        while (!atomic_stop_server) {
            SessionState session_state { SessionState::WAIT_FOR_CONNECTION };
            auto poll_ret = poll(&pfd, 1, 5000);
            if (poll_ret < 0) {
                perror(nullptr);
                throw std::runtime_error("Failed to poll on Shadow Server socket");
            }
            if (poll_ret == 0) continue; // timeout, check for stop
            assert (poll_ret == 1);
            
            cliaddr_len = sizeof(cli_addr);
            int cli_sock;
            if ( (cli_sock = accept(srv_socket, (struct sockaddr *)&cli_addr, &cliaddr_len)) < 0) {
                perror(nullptr);
                continue;
            }
            
            assert(session_state == SessionState::WAIT_FOR_CONNECTION);
            session_state = SessionState::ESTABLISH_SESSION;
            
            // check if IPv4 address
            if (cli_addr.sin_family != AF_INET || cliaddr_len != sizeof(cli_addr)) {
                std::cerr << "Client Address has to be IPv4 at the moment" << std::endl;
                close(cli_sock);
            }
            
#ifdef DEBUG_SHADOWER
            std::cout << "New Client has connected to Shadow Server: "
            << inet_ntoa(cli_addr.sin_addr) << ":" << ntohs(cli_addr.sin_port) << std::endl;
#endif
            
            assert(session_state == SessionState::ESTABLISH_SESSION);
            session_state = SessionState::ACTIVE_SESSION;
            
            try {
                handle_connection(cli_sock, cli_addr, session_state);
            } catch (std::exception &e) {
                std::cerr << "Handling client connection produced an error: " << e.what()
                << " (state number: " <<  int(session_state) << ")" << std::endl;
                session_state = SessionState::FINISHING_SESSION;
            }
            
            assert(session_state == SessionState::FINISHING_SESSION);
            close(cli_sock);
        }
        
#ifdef DEBUG_SHADOWER
        std::cout << "Finishing CliSockShadow Server listen loop" << std::endl;
#endif
        
        // TODO: when to clean up the iptable rules?
    }
    
    void CliSockShadower::send_stop_signal() {
        atomic_stop_server = true;
    }
    
    optional<uint32_t>
    CliSockShadower::receive_protobuf_message(int sockfd, std::vector<unsigned char> &buf) {
        // must be able to receive the message length
        if (buf.size() < 4) return {};
        ssize_t recv_len {};
        // receive length of message
        if( (recv_len = recv(sockfd, buf.data(), 4, MSG_WAITALL)) < 0) {
            perror(nullptr);
            return {};
        }
        if (recv_len != 4) return {};
        
        uint32_t protobuf_len { * ((uint32_t *)buf.data()) };
        // check whether buffer can receive whole message
        if( buf.size() < protobuf_len ) return {};
        
        // receive the actual message
        if( (recv_len = recv(sockfd, buf.data(), protobuf_len, MSG_WAITALL)) < 0) {
            perror(nullptr);
            return {};
        }
        if (recv_len != protobuf_len) return {};
        
        return make_optional(protobuf_len);
    }
    
    bool CliSockShadower::send_protobuf_message(int sockfd, std::string &msg) {
        // Send message length first
        uint32_t msg_len = msg.size();
        ssize_t missing_bytes { 4 };
        
        ssize_t sent_bytes { 0 };
        auto p = (unsigned char *)&msg_len;
        while (missing_bytes > 0) {
            if( (sent_bytes = send(sockfd, p, missing_bytes, 0)) < 0) {
                perror(nullptr);
                return false;
            }
            missing_bytes -= sent_bytes;
            p += sent_bytes;
        }
        
        // Send actual protobuf msg
        missing_bytes = msg_len;
        p = (unsigned char *)msg.data();
        while (missing_bytes > 0) {
            if( (sent_bytes = send(sockfd, p, missing_bytes, 0)) < 0) {
                perror(nullptr);
                return false;
            }
            missing_bytes -= sent_bytes;
            p += sent_bytes;
        }
        
        return true;
    }
    
    void CliSockShadower::handle_connection(int enc_sock, struct sockaddr_in enc_addr, SessionState &session_state) {
        assert(session_state == SessionState::ACTIVE_SESSION);
        session_state = SessionState::WAIT_FOR_REQ_MSG;
        
        // Check that IP indeed belongs to an active Enclave connected to us
        if (!enclave_idx_sp->is_active_enclave(enc_addr.sin_addr.s_addr)) {
            std::cerr << "The client IP does NOT belong to an active Enclave" << std::endl;
            session_state = SessionState::FINISHING_SESSION;
            return;
        }
        
        // Set receive timeout
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(enc_sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        
        // Try to receive Protobuf request message
        std::vector<unsigned char> buf(128);
        auto opt_msg_len { CliSockShadower::receive_protobuf_message(enc_sock, buf) };
        if( !opt_msg_len ) {
            std::cerr << "Failed to receive the client request message" << std::endl;
            session_state = SessionState::FINISHING_SESSION;
            return;
        }
        
        assert(session_state == SessionState::WAIT_FOR_REQ_MSG);
        session_state = SessionState::CHECK_VALID_REQUEST;
        
        // Try to parse ShadowSrv msg
        seng_proto::ShadowSrvMsg wrap_msg;
        if( wrap_msg.ParseFromArray(buf.data(), *opt_msg_len) ) {
#ifdef DEBUG_SHADOWER
            std::cout << "Received message from Enclave" << std::endl;
#endif
        } else {
            std::cerr << "Failed to parse Request Message of Enclave" << std::endl;
            assert(session_state == SessionState::CHECK_VALID_REQUEST);
            session_state = SessionState::FINISHING_SESSION;
            return;
        }

        switch (wrap_msg.msg_case()) {
            case seng_proto::ShadowSrvMsg::kReqShadow:
#ifdef DEBUG_SHADOWER
                std::cout << "Received Shadowing request by Enclave" << std::endl;
#endif
                
                assert(session_state == SessionState::CHECK_VALID_REQUEST);
                session_state = SessionState::SHADOW_REQ__START_PROCESSING;
                
                handle_shadow_request(enc_sock, enc_addr, session_state, buf,
                                      wrap_msg.reqshadow());
                
                assert(session_state == SessionState::SHADOW_REQ__SUCCESS ||
                       session_state == SessionState::SHADOW_REQ__FAILED);
                break;
            
            case seng_proto::ShadowSrvMsg::kCloseNotify: {
#ifdef DEBUG_SHADOWER
                std::cout << "Received close notification by Enclave" << std::endl;
#endif
                
                assert(session_state == SessionState::CHECK_VALID_REQUEST);
                session_state = SessionState::CLOSE_NOTIFY__START_PROCESSING;
                
                /*
                 * TODO:  We currently don't remove ShadowRules automatically;
                 */
                session_state = SessionState::CLOSE_NOTIFY__SUCCESS;
                //handle_close_notification(enc_sock, enc_addr, session_state, buf,
                //                          wrap_msg.closenotify());
                
                assert(session_state == SessionState::CLOSE_NOTIFY__SUCCESS ||
                       session_state == SessionState::CLOSE_NOTIFY__FAILED);
                break;
            }
                
            case seng_proto::ShadowSrvMsg::MSG_NOT_SET:
                std::cerr << "No valid ShadowSrvMsg sent by client" << std::endl;
                assert(session_state == SessionState::CHECK_VALID_REQUEST);
                session_state = SessionState::FINISHING_SESSION;
                return;
        }
        
#ifdef DEBUG_SHADOWER
        // display return value
        if (session_state == SessionState::SHADOW_REQ__SUCCESS || session_state == SessionState::CLOSE_NOTIFY__SUCCESS) {
            std::cout << "Successfully finished the Enclave request" << std::endl;
        } else if (session_state == SessionState::SHADOW_REQ__FAILED || session_state == SessionState::CLOSE_NOTIFY__FAILED) {
            std::cout << "A protocol error has occurred during the Enclave interaction" << std::endl;
        }
#endif
        
        session_state = SessionState::FINISHING_SESSION;
    }
    
    
    void
    CliSockShadower::handle_shadow_request(int enc_sock, struct sockaddr_in enc_addr,
                                           SessionState &session_state,
                                           std::vector<unsigned char> &buf,
                                           const seng_proto::ShadowSrvMsg_RequestCliSockShadowing &shadow_msg) {
        
        assert(session_state == SessionState::SHADOW_REQ__START_PROCESSING);
        
        // check whether valid port and protocol
        if (!is_supported_protocol(shadow_msg.proto()) ||
            !is_in_port_range(shadow_msg.port())) {
            assert(session_state == SessionState::SHADOW_REQ__START_PROCESSING);
            session_state = SessionState::SHADOW_REQ__FAILED;
            std::cerr << "Port-Protocol combination is invalid" << std::endl;
            return;
        }

        assert(session_state == SessionState::SHADOW_REQ__START_PROCESSING);
        session_state = SessionState::SHADOW_REQ__CHECK_WHETHER_ALREADY_SHADOWED;
        
        // Get and print corresponding client host IP
        auto opt_cli_ip = enclave_idx_sp->get_ip_of_enclaves_tunnel_host(enc_addr.sin_addr.s_addr);
        if (!opt_cli_ip) {
            assert(session_state == SessionState::SHADOW_REQ__CHECK_WHETHER_ALREADY_SHADOWED);
            session_state = SessionState::SHADOW_REQ__FAILED;
            std::cerr << "Failed to get IP of underlying host" << std::endl;
            return;
        }
        in_addr_t untrusted_host_ip { *opt_cli_ip };
#ifdef DEBUG_SHADOWER
        std::cout << "IP of Enclave's (untrusted) tunnel host: " << inet_ntoa({untrusted_host_ip}) << std::endl;
#endif
        
        // Check whether already shadowed
        if (enclave_idx_sp->is_already_shadowed(shadow_msg.port(), shadow_msg.proto(), untrusted_host_ip)) {
            assert(session_state == SessionState::SHADOW_REQ__CHECK_WHETHER_ALREADY_SHADOWED);
            session_state = SessionState::SHADOW_REQ__FAILED;
            std::cerr << "(" << ntohs(shadow_msg.port()) << ", " <<
            (shadow_msg.proto() == IPPROTO_TCP ? "tcp" : "non-tcp") << ") is already shadowed" << std::endl;
            return;
        }
        
        assert(session_state == SessionState::SHADOW_REQ__CHECK_WHETHER_ALREADY_SHADOWED);
        session_state = SessionState::SHADOW_REQ__CONNECT_TO_CLISB;
        
        // connect to CliSB
        auto opt_ctx_pair = connect_to_client_sock_blocker(untrusted_host_ip);
        if (!opt_ctx_pair) {
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
        std::unique_ptr<mbedtls_net_context> &net_ptr = opt_ctx_pair->first;
        std::unique_ptr<mbedtls_ssl_context> &ssl_ptr = opt_ctx_pair->second;
        
        assert(session_state == SessionState::SHADOW_REQ__CONNECT_TO_CLISB);
        session_state = SessionState::SHADOW_REQ__SEND_BLOCK_REQ_TO_CLISB;
        
        // send block request to clisb
        seng_proto::CliBlockerMsg cli_wrap_msg;
        auto cli_block_req = new seng_proto::CliBlockerMsg_RequestSockBlocking();
        cli_block_req->set_port(shadow_msg.port());
        cli_block_req->set_proto(shadow_msg.proto());
        
        sgx_quote_t quote;
        try {
            // optional would be cooler, but somehow experimental/optional does not like signature[]
            quote = enclave_idx_sp->get_enclave_quote(enc_addr.sin_addr.s_addr);
        } catch(...) {
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            std::cerr << "[CAUTION] Failed to get Quote of Enclave (Tunnel Closed during handling?)" << std::endl;
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
        
        // TODO: unclear whether this works w/o unexpected value transformations
        std::string mr_enclave((char *)quote.report_body.mr_enclave.m, SGX_HASH_SIZE);
        std::string mr_signer((char *)quote.report_body.mr_signer.m, SGX_HASH_SIZE);
        
        cli_block_req->set_mr_enclave(mr_enclave);
        cli_block_req->set_mr_signer(mr_signer);
        cli_wrap_msg.set_allocated_sockblock(cli_block_req);
        
        // Send block request message to CliSB
        std::string msg_ngw_clisb;
        if( !cli_wrap_msg.SerializeToString(&msg_ngw_clisb) || !ssl_send_protomsg(ssl_ptr.get(), msg_ngw_clisb) ) {
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            std::cerr << "Failed to send message to untrusted tunnel host" << std::endl;
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
        
#ifdef DEBUG_SHADOWER
        std::cout << "Successfully sent message to untrusted tunnel host" << std::endl;
#endif
        
        assert(session_state == SessionState::SHADOW_REQ__SEND_BLOCK_REQ_TO_CLISB);
        session_state = SessionState::SHADOW_REQ__WAIT_FOR_CLISB_REPLY;
        
        // Wait for reply msg of CliSB
        seng_proto::CliBlockerReply clisb_reply;
        auto opt_msg_len { ssl_receive_protomsg(ssl_ptr.get(), buf) };
        if (!opt_msg_len || !clisb_reply.ParseFromArray(buf.data(), *opt_msg_len)) {
            std::cerr << "Failed to receive the reply from CliSB on request" << std::endl;
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
        
        // Create rule object
        struct in_addr only_for_our_setup_needed_middlebox_ip;
        auto tmp = inet_aton("192.168.178.45", &only_for_our_setup_needed_middlebox_ip);
        assert(tmp != 0);
        ShadowRule rule { static_cast<in_port_t>(shadow_msg.port()),
            static_cast<uint8_t>(shadow_msg.proto()),
            enc_addr.sin_addr.s_addr,
            //untrusted_host_ip
            // TODO: we currently have to use middlebox IP instead, bcs. we need NATed setup as middlebox not runs on "real" gateway
            only_for_our_setup_needed_middlebox_ip.s_addr,
        };
        
        assert(session_state == SessionState::SHADOW_REQ__WAIT_FOR_CLISB_REPLY);
        switch (clisb_reply.reply()) {
            case seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_IN_USE:
#ifdef DEBUG_SHADOWER
                std::cout << "The untrusted host seems to already block the requested port" << std::endl;
#endif
                session_state = SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC;
                break;
                
            case seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_GRANTED:
#ifdef DEBUG_SHADOWER
                std::cout << "Socket shadowing has been GRANTED by the untrusted host" << std::endl;
#endif
                session_state = SessionState::SHADOW_REQ__PROBE_RULES_INTEGRATION;
                
                // Try to integrate rule into system (reservation)
                if (!rule.add_to_system()) {
                    assert(session_state == SessionState::SHADOW_REQ__PROBE_RULES_INTEGRATION);
                    session_state = SessionState::SHADOW_REQ__ABORT_DUE_TO_INTEGRATION_ERROR;
                    
                    assert(rule.get_state() == RuleState::DISABLED);
                    
                    std::cerr << "Probing of new rule w.r.t. system integration failed. Will now abort." << std::endl;
                    shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
                    
                    assert(session_state == SessionState::SHADOW_REQ__ABORT_DUE_TO_INTEGRATION_ERROR);
                    session_state = SessionState::SHADOW_REQ__FAILED;
                    return;
                    
                } else {
                    assert(session_state == SessionState::SHADOW_REQ__PROBE_RULES_INTEGRATION);
                    session_state = SessionState::SHADOW_REQ__SEND_GRANTED_TO_ENC;
                    
                    assert(rule.get_state() == RuleState::ENABLED);
                }
                break;
                
            case seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_DENIED:
#ifdef DEBUG_SHADOWER
                std::cout << "Socket shadowing has been denied by the untrusted host" << std::endl;
#endif
                session_state = SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC;
                break;
                
            default:
                std::cerr << "Received unexpected reply from CliSB" << std::endl;
                shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
                session_state = SessionState::SHADOW_REQ__FAILED;
                return;
        }
  
        assert(session_state == SessionState::SHADOW_REQ__SEND_GRANTED_TO_ENC ||
               session_state == SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC);

        // Send protobuf reply message to Enclave
        seng_proto::ShadowReqReply reply_msg;
        std::string msg_enc_ngw;
        if (session_state == SessionState::SHADOW_REQ__SEND_GRANTED_TO_ENC) {
            reply_msg.set_reply(seng_proto::ShadowReqReply_Replies::ShadowReqReply_Replies_GRANTED);
        } else if (session_state == SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC) {
            reply_msg.set_reply(seng_proto::ShadowReqReply_Replies::ShadowReqReply_Replies_DENIED);
        }

        if( !reply_msg.SerializeToString(&msg_enc_ngw) || !send_protobuf_message(enc_sock, msg_enc_ngw) ) {
            std::cerr << "Failed to send reply message to Enclave" << std::endl;
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            assert(rule.get_state() == RuleState::ENABLED);
            if (!rule.delete_from_system()) std::cerr << "[WARNING] Failed to delete ShadowRule on error" << std::endl;
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
#ifdef DEBUG_SHADOWER
        std::cout << "Succesfully sent out reply to Enclave" << std::endl;
#endif
        
        assert(session_state == SessionState::SHADOW_REQ__SEND_GRANTED_TO_ENC ||
               session_state == SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC);
        
        // Informed Enclave about denial, so end session.
        if (session_state == SessionState::SHADOW_REQ__SEND_DENIED_TO_ENC) {
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            assert(rule.get_state() == RuleState::DISABLED);
            session_state = SessionState::SHADOW_REQ__SUCCESS;
            return;
        }
        
        assert(session_state == SessionState::SHADOW_REQ__SEND_GRANTED_TO_ENC);
        session_state = SessionState::SHADOW_REQ__WAIT_FOR_CONFIRM_MSG_BY_ENC;
        
        // Wait for Client lwip_listen success confirmation
        seng_proto::ListenStartConfirm confirm_msg;
        opt_msg_len = CliSockShadower::receive_protobuf_message(enc_sock, buf);
        if( !opt_msg_len || !confirm_msg.ParseFromArray(buf.data(), *opt_msg_len) ) {
            std::cerr << "Failed to receive the Enclave confirmation message" << std::endl;
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            assert(rule.get_state() == RuleState::ENABLED);
            if (!rule.delete_from_system()) std::cerr << "[WARNING] Failed to delete ShadowRule on error" << std::endl;
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
        
        // Check confirmation status
        switch (confirm_msg.reply()) {
            case seng_proto::ListenStartConfirm_Replies_NOW_LISTENING:
#ifdef DEBUG_SHADOWER
                std::cout << "Enclave succesfully started listening, so we can keep forwarding the requests, and inform the client to keep blocking the port." << std::endl;
#endif
                break;
                
            case seng_proto::ListenStartConfirm_Replies_FAILED:
                std::cerr << "Enclave failed to start listening, so rollback forward rules, and inform client to unblock the socket" << std::endl;
                break;
        }
        
        assert(session_state == SessionState::SHADOW_REQ__WAIT_FOR_CONFIRM_MSG_BY_ENC);
        session_state = SessionState::SHADOW_REQ__FWD_CONFIRM_TO_CLISB;
        
        // Forward confirm message to CliSB
        confirm_msg.SerializeToString(&msg_ngw_clisb);
        if( !ssl_send_protomsg(ssl_ptr.get(), msg_ngw_clisb) ) {
            std::cerr << "Failed to forward Enclave Listen-Confirmation message to CliSB" << std::endl;
            shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
            assert(rule.get_state() == RuleState::ENABLED);
            if (!rule.delete_from_system()) std::cerr << "[WARNING] Failed to delete ShadowRule on error" << std::endl;
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }
 
        assert(session_state == SessionState::SHADOW_REQ__FWD_CONFIRM_TO_CLISB);
        session_state = SessionState::SHADOW_REQ__COMMIT_SHADOW_RULES;
        
        // Shutdown connection to Client Socket Blocker
        shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
        
        // Commit rule to our database/lists
        assert(rule.get_state() == RuleState::ENABLED);
        if (!enclave_idx_sp->commit_shadow_rule(rule)) {
            // Could only occur if an other thread suddenly added a conflicting rule,
            // or the rule state was disabled and enabling failed.
            std::cerr << "[CAUTION] Failed to commit the shadow rule! This is a fatal error!" << std::endl;
            if (rule.get_state() == RuleState::ENABLED && !rule.delete_from_system()) {
                std::cerr << "[WARNING] Failed to delete ShadowRule on error" << std::endl;
            }
            session_state = SessionState::SHADOW_REQ__FAILED;
            return;
        }

        assert(session_state == SessionState::SHADOW_REQ__COMMIT_SHADOW_RULES);
        session_state = SessionState::SHADOW_REQ__SUCCESS;
        
        assert(rule.get_state() == RuleState::ENABLED);
    }
    
    
    void
    CliSockShadower::handle_close_notification(int enc_sock, struct sockaddr_in enc_addr,
                                               SessionState &session_state,
                                               std::vector<unsigned char> &buf,
                                               const seng_proto::ShadowSrvMsg_NotifyAboutClose &close_msg) {
        
        assert(session_state == SessionState::CLOSE_NOTIFY__START_PROCESSING);
        session_state = SessionState::CLOSE_NOTIFY__CHECK_WHETHER_WAS_SHADOWED;
        
        // Get and print corresponding client host IP
        auto opt_cli_ip = enclave_idx_sp->get_ip_of_enclaves_tunnel_host(enc_addr.sin_addr.s_addr);
        if (!opt_cli_ip) {
            assert(session_state == SessionState::CLOSE_NOTIFY__CHECK_WHETHER_WAS_SHADOWED);
            session_state = SessionState::CLOSE_NOTIFY__FAILED;
            std::cerr << "Failed to get IP of underlying host" << std::endl;
            return;
        }
        in_addr_t untrusted_host_ip { *opt_cli_ip };
#ifdef DEBUG_SHADOWER
        std::cout << "IP of Enclave's (untrusted) tunnel host: " << inet_ntoa({untrusted_host_ip}) << std::endl;
#endif
        
        // TODO: check whether shadowed, and retrieve (port, proto) (we do not have a corresponding data/api, yet)
        const auto &h = close_msg.handle();
        /*
        auto r = enclave_idx_sp->get_shadow_rule(h, enc_addr.sin_addr.s_addr);
        if (!r) {
            assert(session_state == SessionState::CLOSE_NOTIFY__CHECK_WHETHER_WAS_SHADOWED);
            session_state = SessionState::CLOSE_NOTIFY__FAILED;
            std::cerr << "No rule matching the CLOSE Notification exists" << std::endl;
            return;
        }
        in_port_t shadowed_port { r->port };
        uint8_t shadowed_proto { r->protocol };
        */
        
        in_port_t shadowed_port {4711};
        uint8_t shadowed_proto {IPPROTO_TCP};
        
        assert(session_state == SessionState::CLOSE_NOTIFY__CHECK_WHETHER_WAS_SHADOWED);
        session_state = SessionState::CLOSE_NOTIFY__CONNECT_TO_CLISB;
        
        // connect to CliSB
        auto opt_ctx_pair = connect_to_client_sock_blocker(untrusted_host_ip);
        if (!opt_ctx_pair) {
            session_state = SessionState::CLOSE_NOTIFY__FAILED;
            return;
        }
        std::unique_ptr<mbedtls_net_context> &net_ptr = opt_ctx_pair->first;
        std::unique_ptr<mbedtls_ssl_context> &ssl_ptr = opt_ctx_pair->second;
        
        assert(session_state == SessionState::CLOSE_NOTIFY__CONNECT_TO_CLISB);
        session_state = SessionState::CLOSE_NOTIFY__SEND_CLOSE_REQ_TO_CLISB;
        
        // Send close notification message to CliSB (TODO: we should prob. only do that after all ESTALBISHED connections are gone?)
        seng_proto::CliBlockerMsg wrap_msg;
        auto notify_clisb = new seng_proto::CliBlockerMsg_CloseNotify();
        notify_clisb->set_port(shadowed_port);
        notify_clisb->set_proto(shadowed_proto);
        wrap_msg.set_allocated_closenotify(notify_clisb);
        
        std::string msg_data;
        if (!wrap_msg.SerializeToString(&msg_data) || !ssl_send_protomsg(ssl_ptr.get(), msg_data)) {
            std::cerr << "Failed to notify CliSB about close of Enclave's Server socket" << std::endl;
            // TODO: there's not much we can do in this situation, right?
        } else {
#ifdef DEBUG_SHADOWER
            std::cout << "Successfully sent close notification to CliSB" << std::endl;
#endif
        }
        
        assert(session_state == SessionState::CLOSE_NOTIFY__SEND_CLOSE_REQ_TO_CLISB);
        session_state = SessionState::CLOSE_NOTIFY__REMOVE_SHADOW_RULE;
        
        shutdown_connection_to_clisb(net_ptr.get(), ssl_ptr.get());
        
        // TODO: we MUST handle ongoing (ESTABLISHED) connections between the Enclave and external hosts before removing the rule(s)
        // TODO: remove shadow rule, and all related data that has been stored
        
        assert(session_state == SessionState::CLOSE_NOTIFY__REMOVE_SHADOW_RULE);
        session_state = SessionState::CLOSE_NOTIFY__SUCCESS;
    }

    
    optional<
    std::pair<
    std::unique_ptr<mbedtls_net_context>,
    std::unique_ptr<mbedtls_ssl_context>
    >
    > CliSockShadower::connect_to_client_sock_blocker(in_addr_t untrusted_host_ip) {
        std::unique_ptr<mbedtls_net_context> net_ctx_ptr {};
        std::unique_ptr<mbedtls_ssl_context> ssl_ctx_ptr {};
        
#ifdef DEBUG_SHADOWER
        std::cout << "Preparing CliSB server addres" << std::endl;
#endif
        
        const char *blocker_service_port { "2834" };
        const char *untrusted_cli_ip = inet_ntoa({ untrusted_host_ip });
        if( untrusted_cli_ip == nullptr ) {
            std::cerr << "Failed to transform IP of untrusted tunnel host" << std::endl;
            return nullopt;
        }
        
        net_ctx_ptr = std::make_unique<mbedtls_net_context>();
        mbedtls_net_init(net_ctx_ptr.get());
        
#ifdef DEBUG_SHADOWER
        std::cout << "Trying to connect to CliSB server" << std::endl;
#endif
        
        if( mbedtls_net_connect(net_ctx_ptr.get(), untrusted_cli_ip, blocker_service_port, MBEDTLS_NET_PROTO_TCP) < 0) {
            perror(nullptr);
            std::cerr << "Connection to untrusted tunnel host failed" << std::endl;
            mbedtls_net_free(net_ctx_ptr.get());
            return nullopt;
        }
        
#ifdef DEBUG_SHADOWER
        std::cout << "Setting up SSL context" << std::endl;
#endif
        
        ssl_ctx_ptr = std::make_unique<mbedtls_ssl_context>();
        mbedtls_ssl_init(ssl_ctx_ptr.get());
        
        if( mbedtls_ssl_setup(ssl_ctx_ptr.get(), &ssl_engine.conf) != 0) {
            perror(nullptr);
            std::cerr << "SSL Setup somehow failed; this shouldn't happen!" << std::endl;
            mbedtls_ssl_free(ssl_ctx_ptr.get());
            mbedtls_net_free(net_ctx_ptr.get());
            return nullopt;
        }
        mbedtls_ssl_set_bio( ssl_ctx_ptr.get(), net_ctx_ptr.get(),
                             mbedtls_net_send, mbedtls_net_recv, NULL );
        
#ifdef DEBUG_SHADOWER
        std::cout << "Trying to handshake with CliSB Server" << std::endl;
#endif
        
        int ret;
        do (ret = mbedtls_ssl_handshake(ssl_ctx_ptr.get()));
        while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        
        if (ret != 0) {
            std::cerr << "Failed SSL Handshake with untrusted tunnel host" << std::endl;
            mbedtls_ssl_free(ssl_ctx_ptr.get());
            mbedtls_net_free(net_ctx_ptr.get());
            return nullopt;
        }
        
#ifdef DEBUG_SHADOWER
        std::cout << "Successfully performed SSL Handhshake with the untrusted tunnel host" << std::endl;
#endif
        
        std::pair<
        std::unique_ptr<mbedtls_net_context>,
        std::unique_ptr<mbedtls_ssl_context>
        > connection_data = std::make_pair(std::move(net_ctx_ptr),
                                           std::move(ssl_ctx_ptr));
        
        return make_optional(std::move(connection_data));
    }
    
    
    optional<uint32_t>
    CliSockShadower::ssl_receive_protomsg(mbedtls_ssl_context *ssl_ctx, std::vector<unsigned char> &buf) {
        // must be able to receive the message length
        if (buf.size() < 4) return {};
        
        ssize_t missing_bytes { 4 };
        int received_bytes { 0 };
        auto p = (unsigned char *)buf.data();
        
        // receive length of message
        while (missing_bytes > 0) {
            do received_bytes = mbedtls_ssl_read(ssl_ctx, p, missing_bytes);
            while (received_bytes == MBEDTLS_ERR_SSL_WANT_READ || received_bytes == MBEDTLS_ERR_SSL_WANT_WRITE);
            
            // failed
            if (received_bytes <= 0) return {};
            
            missing_bytes -= received_bytes;
            p += received_bytes;
        }
        uint32_t protobuf_len { * ((uint32_t *)buf.data()) };
        
        // check whether buffer can receive whole message
        if( buf.size() < protobuf_len ) return {};
        
        // receive the actual message
        missing_bytes = protobuf_len;
        p = (unsigned char *)buf.data();
        while (missing_bytes > 0) {
            do received_bytes = mbedtls_ssl_read(ssl_ctx, p, missing_bytes);
            while (received_bytes == MBEDTLS_ERR_SSL_WANT_READ || received_bytes == MBEDTLS_ERR_SSL_WANT_WRITE);
            
            // failed
            if (received_bytes <= 0) return {};
            
            missing_bytes -= received_bytes;
            p += received_bytes;
        }
        
        return make_optional(protobuf_len);
    }
    
    bool CliSockShadower::ssl_send_protomsg(mbedtls_ssl_context *ssl_ctx, std::string &msg) {
        // Send message length first
        uint32_t msg_len = msg.size();
        ssize_t missing_bytes { 4 };
        
        ssize_t sent_bytes { 0 };
        auto p = (unsigned char *)&msg_len;
        while (missing_bytes > 0) {
            do sent_bytes = mbedtls_ssl_write(ssl_ctx, p, missing_bytes);
            while (sent_bytes == MBEDTLS_ERR_SSL_WANT_READ || sent_bytes == MBEDTLS_ERR_SSL_WANT_WRITE);
            
            // failed
            if (sent_bytes <= 0) return false;
            
            missing_bytes -= sent_bytes;
            p += sent_bytes;
        }
        
        // Send actual protobuf msg
        missing_bytes = msg_len;
        p = (unsigned char *)msg.data();
        while (missing_bytes > 0) {
            do sent_bytes = mbedtls_ssl_write(ssl_ctx, p, missing_bytes);
            while (sent_bytes == MBEDTLS_ERR_SSL_WANT_READ || sent_bytes == MBEDTLS_ERR_SSL_WANT_WRITE);;
            
            // failed
            if (sent_bytes <= 0) return false;
            
            missing_bytes -= sent_bytes;
            p += sent_bytes;
        }
        
        return true;
    }
    
    bool CliSockShadower::is_supported_protocol(uint8_t proto) {
        // Check that protocol is either TCP or UDP
        return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
    }
    
    bool CliSockShadower::is_in_port_range(in_port_t port) {
        // Check that port number is not out of range
        return port <= std::numeric_limits<uint16_t>::max();
    }
    
    void CliSockShadower::shutdown_connection_to_clisb(mbedtls_net_context *net_ctx,
                                                       mbedtls_ssl_context *ssl_ctx) {
        int ret;
        do ret = mbedtls_ssl_close_notify(ssl_ctx);
        while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
        
        mbedtls_ssl_free(ssl_ctx);
        mbedtls_net_free(net_ctx);
    }
}
