#include <iostream>

#include "SSLEngine.hpp"

#include <mbedtls/certs.h>
#include <mbedtls/net_sockets.h>

#include <arpa/inet.h>

#include <cassert>

#include <unistd.h>

#include <limits>

#include <vector>
#include <string>

#include <map>

#include <csignal>

#include <sgx_report.h>

#include "seng.pb.h"

#include <experimental/optional>

using namespace std::experimental;


volatile sig_atomic_t stop_marker {0};

static void stop_marker_sighandler(int signum) {
    stop_marker++;
}

enum class SessionState {
    WAIT_FOR_CONNECTION = 0,
    ESTABLISH_SESSION,
    ACTIVE_SESSION,
    
    WAIT_FOR_REQ_MSG,
    CHECK_VALID_REQUEST,
    
    FINISHING_SESSION,
    
    CLOSE_REQ__START_PROCESSING,
    CLOSE_REQ__CHECK_WHETHER_BLOCKED,
    CLOSE_REQ__SEND_WAS_NOT_BLOCKED,
    CLOSE_REQ__UNBLOCK,
    CLOSE_REQ__SEND_NOW_UNLBOCKED,
    CLOSE_REQ__SUCCESS,
    CLOSE_REQ__FAILED,
    
    BLOCK_REQ__START_PROCESSING,
    BLOCK_REQ__CHECK_WHETHER_ALLOWED,       // TODO: ask user / look up in policy file/db
    BLOCK_REQ__SEND_DENIED,
    BLOCK_REQ__CHECK_WHETHER_RESERVABLE,    // check whether not blocked, socket() && bind() works
    BLOCK_REQ__SEND_IN_USE,                 // either blocked by us, or bind() failed
    BLOCK_REQ__SEND_GRANTED,
    BLOCK_REQ__RECV_CONFIRMATION,           // whether Enclave and NGW successfully finished their parts
    BLOCK_REQ__UNDO_RESERVE,                // close() socket again
    BLOCK_REQ__BLOCK,                       // create BlockInfo object and add it to our blocking list
    BLOCK_REQ__SUCCESS,
    BLOCK_REQ__FAILED,
};


static void handle_client_session(mbedtls_ssl_context *ssl_ctx, SessionState &session_state);
void handle_socket_block_request(mbedtls_ssl_context *ssl_ctx, SessionState &session_state,
                                 const seng_proto::CliBlockerMsg_RequestSockBlocking &block_msg);
void handle_close_request(mbedtls_ssl_context *ssl_ctx, SessionState &session_state,
                         const seng_proto::CliBlockerMsg_CloseNotify &close_msg);

bool is_supported_protocol(uint8_t proto);
bool is_in_port_range(in_port_t port);

void cleanup_block_sockets();

static optional<uint32_t> receive_protobuf_message(mbedtls_ssl_context *ssl_ctx, std::vector<unsigned char> &buf);
static bool send_protobuf_message(mbedtls_ssl_context *ssl_ctx, std::string &msg);


struct BlockInfo {
    int sockfd;
    in_port_t port;
    uint8_t proto;
    sgx_measurement_t mr_enclave;
    sgx_measurement_t mr_signer;
};

std::map<in_port_t, BlockInfo> tcp_block_map {};
std::map<in_port_t, BlockInfo> udp_block_map {};


int main(int argc, char *argv[]) {
    std::cout << "Welcome to the Client Socket Blocker" << std::endl;
 
    struct sigaction sigint_handler {
        .__sigaction_handler = { stop_marker_sighandler },
    };
    
    if( sigaction(SIGINT, &sigint_handler, nullptr) < 0 ) {
        perror(nullptr);
        std::cerr << "Failed to install SIGINT handler" << std::endl;
        return EXIT_FAILURE;
    }
    
    seng::SSLEngine ssl_engine { seng::SSLType::TLS };
    ssl_engine.configure((const unsigned char *) mbedtls_test_srv_crt, mbedtls_test_srv_crt_len,
                         (const unsigned char*) mbedtls_test_cas_pem, mbedtls_test_cas_pem_len,
                         (const unsigned char *) mbedtls_test_srv_key, mbedtls_test_srv_key_len,
                         nullptr, 0,
                         nullptr,
                         true); // server
    
    mbedtls_net_context srv_sock;
    mbedtls_net_init(&srv_sock);
    
    const char *ip = "127.0.0.1";
    const char *port = "2834";
    
    std::cout << "Binding Server socket to " << ip << "/tcp" << ":" << port << std::endl;
    
    if( mbedtls_net_bind(&srv_sock, ip, port, MBEDTLS_NET_PROTO_TCP) < 0 ) {
        perror(nullptr);
        std::cerr << "Binding to " << ip << ":" << port << " failed" << std::endl;
        mbedtls_net_free(&srv_sock);
        return EXIT_FAILURE;
    }
    
    while (stop_marker == 0) {
        SessionState session_state {SessionState::WAIT_FOR_CONNECTION};
        
        mbedtls_net_context client_fd;
        mbedtls_net_init(&client_fd);
        
        std::cout << "Starting listening for new Client..." << std::endl;
        
        if( mbedtls_net_accept(&srv_sock, &client_fd, nullptr, 0, nullptr) < 0) {
            perror(nullptr);
            std::cerr<< "Failed to accept incoming client connection" << std::endl;
            mbedtls_net_free(&client_fd);
            continue;
        }
        
        std::cout << "New client has connected" << std::endl;
        assert(session_state == SessionState::WAIT_FOR_CONNECTION);
        session_state = SessionState::ESTABLISH_SESSION;
        
        mbedtls_ssl_context ssl_ctx;
        mbedtls_ssl_init(&ssl_ctx);
        
        if( mbedtls_ssl_setup(&ssl_ctx, &ssl_engine.conf) != 0) {
            perror(nullptr);
            std::cerr << "SSL Setup somehow failed; this shouldn't happen!" << std::endl;
            mbedtls_ssl_free(&ssl_ctx);
            mbedtls_net_free(&client_fd);
            continue;
        }
        mbedtls_ssl_set_bio( &ssl_ctx, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
        
        int ret;
        do (ret = mbedtls_ssl_handshake(&ssl_ctx));
        while ( (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
               && stop_marker == 0);

        if (ret != 0) {
            std::cerr << "Failed SSL Handshake with Client" << std::endl;
            mbedtls_ssl_free(&ssl_ctx);
            mbedtls_net_free(&client_fd);
            continue;
        }
        
        std::cout << "Successfully performed SSL Handhshake with the new Client" << std::endl;
        assert(session_state == SessionState::ESTABLISH_SESSION);
        session_state = SessionState::ACTIVE_SESSION;
        
        handle_client_session(&ssl_ctx, session_state);
        
        assert(session_state == SessionState::FINISHING_SESSION);
        
        mbedtls_ssl_close_notify(&ssl_ctx);
        mbedtls_ssl_free(&ssl_ctx);
        mbedtls_net_free(&client_fd);
        
        std::cout << "Finished Client Session" << std::endl << std::endl;
    }
    
    std::cout << "Exiting the server with stop_marker: " << stop_marker << std::endl;
    mbedtls_net_free(&srv_sock);
    
    // gracefully cleanup the sockets that we still use for blocking
    cleanup_block_sockets();
    
    std::cout << "Goodbye" << std::endl;
    return EXIT_SUCCESS;
}

void handle_client_session(mbedtls_ssl_context *ssl_ctx, SessionState &session_state) {
    assert(session_state == SessionState::ACTIVE_SESSION);
    session_state = SessionState::WAIT_FOR_REQ_MSG;
    
    std::vector<unsigned char> buf(768);
    auto opt_msg_len = receive_protobuf_message(ssl_ctx, buf);
    if( !opt_msg_len ) {
        std::cerr << "Failed to receive (length, msg) from Client" << std::endl;
        session_state = SessionState::FINISHING_SESSION;
        return;
    }
    
    assert(session_state == SessionState::WAIT_FOR_REQ_MSG);
    session_state = SessionState::CHECK_VALID_REQUEST;
    
    seng_proto::CliBlockerMsg wrap_msg;
    if(! wrap_msg.ParseFromArray(buf.data(), *opt_msg_len) ) {
        std::cerr << "Received unknown protobuf(?) message from Client" << std::endl;
        session_state = SessionState::FINISHING_SESSION;
        return;
    }
    
    switch( wrap_msg.msg_case() ) {
        case seng_proto::CliBlockerMsg::kSockBlock:
            assert(session_state == SessionState::CHECK_VALID_REQUEST);
            session_state = SessionState::BLOCK_REQ__START_PROCESSING;
            
            handle_socket_block_request(ssl_ctx, session_state, wrap_msg.sockblock());
            
            assert(session_state == SessionState::BLOCK_REQ__SUCCESS ||
                   session_state == SessionState::BLOCK_REQ__FAILED);
            break;
            
        case seng_proto::CliBlockerMsg::kCloseNotify:
            assert(session_state == SessionState::CHECK_VALID_REQUEST);
            session_state = SessionState::CLOSE_REQ__START_PROCESSING;
            
            handle_close_request(ssl_ctx, session_state, wrap_msg.closenotify());
            
            assert(session_state == SessionState::CLOSE_REQ__SUCCESS ||
                   session_state == SessionState::CLOSE_REQ__FAILED);
            break;
            
        case seng_proto::CliBlockerMsg::MSG_NOT_SET:
            std::cerr << "Client has sent an empty message" << std::endl;
            
            assert(session_state == SessionState::CHECK_VALID_REQUEST);
            session_state = SessionState::FINISHING_SESSION;
            return;
    }
    
    // display return value
    if (session_state == SessionState::BLOCK_REQ__SUCCESS || session_state == SessionState::CLOSE_REQ__SUCCESS) {
        std::cout << "Successfully finished the client interaction" << std::endl;
    } else if (session_state == SessionState::BLOCK_REQ__FAILED || session_state == SessionState::CLOSE_REQ__FAILED) {
        std::cout << "A protocol error has occurred during the client interaction" << std::endl;
    }
    
    session_state = SessionState::FINISHING_SESSION;
}

void handle_socket_block_request(mbedtls_ssl_context *ssl_ctx, SessionState &session_state,
                                 const seng_proto::CliBlockerMsg_RequestSockBlocking &block_msg) {
    assert(session_state == SessionState::BLOCK_REQ__START_PROCESSING);

    std::cout << std::endl << "Block Request:" << std::endl
    << "Port: \t\t" << ntohs(block_msg.port()) << std::endl
    << "Proto: \t\t" << ((block_msg.proto() == IPPROTO_TCP) ? ("tcp") : ("udp"))
    << std::endl;
    
    std::cout << "MR ENCLAVE: ";
    for (unsigned char c : block_msg.mr_enclave()) {
        printf("%02x", c);
    }
    std::cout << std::endl
    << "MR SIGNER: ";
    for (unsigned char c : block_msg.mr_signer()) {
        printf("%02x", c);
    }
    std::cout << std::endl << std::endl;
    
    // Check that protocol is either TCP or UDP
    if (!is_supported_protocol(block_msg.proto())) {
        assert(session_state == SessionState::BLOCK_REQ__START_PROCESSING);
        session_state = SessionState::BLOCK_REQ__FAILED;
        std::cerr << "Only TCP or UDP ports can be blocked" << std::endl;
        return;
    }
    
    // Check that port number is not out of range
    if (!is_in_port_range(block_msg.port())) {
        assert(session_state == SessionState::BLOCK_REQ__START_PROCESSING);
        session_state = SessionState::BLOCK_REQ__FAILED;
        std::cerr << "Port is out of 16bit max. range" << std::endl;
        return;
    }
    
    // Check that MRENCLAVE and MRSIGNER have respective lengths
    if (block_msg.mr_enclave().size() != SGX_HASH_SIZE ||
        block_msg.mr_signer().size()  != SGX_HASH_SIZE) {
        assert(session_state == SessionState::BLOCK_REQ__START_PROCESSING);
        session_state = SessionState::BLOCK_REQ__FAILED;
        std::cerr << "At leaste one of the measurement values has unexpected length" << std::endl;
        return;
    }
    
    assert(session_state == SessionState::BLOCK_REQ__START_PROCESSING);
    session_state = SessionState::BLOCK_REQ__CHECK_WHETHER_ALLOWED;
    
    // TODO: add permission check: ask user or look up in database
    //if (block_msg.mr_enclave() != "foobar" ||
    //    block_msg.mr_signer() != "deadbeef") {
    if (false) {
        assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_ALLOWED);
        session_state = SessionState::BLOCK_REQ__SEND_DENIED;
        std::cout << "Permission REJECTED" << std::endl;
    } else {
        assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_ALLOWED);
        session_state = SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE;
        std::cout << "Permission ALLOWED" << std::endl;
    }

    int reserve_sockfd {-1};
    struct sockaddr_in reserve_addr {
        .sin_family = AF_INET,
        .sin_port = static_cast<in_port_t>(block_msg.port()),
        .sin_addr = {0}, // TODO
    };
    
    if (session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE) {
        // check whether our service already is blocking the port:proto combi
        if ( (block_msg.proto() == IPPROTO_TCP && tcp_block_map.count(static_cast<in_port_t>(block_msg.port())) > 0) ||
             (block_msg.proto() == IPPROTO_UDP && udp_block_map.count(static_cast<in_port_t>(block_msg.port())) > 0)) {
            assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE);
            session_state = SessionState::BLOCK_REQ__SEND_IN_USE;
            std::cerr << "We are already blocking this port:proto combination" << std::endl;
            close(reserve_sockfd);
            
        } else {
            reserve_sockfd = socket(AF_INET, (block_msg.proto() == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM) , 0);
            // socket creation
            if (reserve_sockfd < 0) {
                assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE);
                session_state = SessionState::BLOCK_REQ__FAILED;
                return;
            }
            // try to bind (TODO: do we also have to set to listen?)
            if (bind(reserve_sockfd, (struct sockaddr *)&reserve_addr, sizeof(reserve_addr)) < 0) {
                assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE);
                session_state = SessionState::BLOCK_REQ__SEND_IN_USE;
                std::cerr << "The system seems to already use the port:proto, or denied blocking" << std::endl;
                close(reserve_sockfd);
            } else {
                assert(session_state == SessionState::BLOCK_REQ__CHECK_WHETHER_RESERVABLE);
                session_state = SessionState::BLOCK_REQ__SEND_GRANTED;
            }
        }
    }
    
    assert(session_state == SessionState::BLOCK_REQ__SEND_DENIED ||
           session_state == SessionState::BLOCK_REQ__SEND_IN_USE ||
           session_state == SessionState::BLOCK_REQ__SEND_GRANTED);
    
    seng_proto::CliBlockerReply reply_msg;
    std::string msg_data;
    switch (session_state) {
        case SessionState::BLOCK_REQ__SEND_DENIED:
            reply_msg.set_reply(seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_DENIED);
            if (!reply_msg.SerializeToString(&msg_data) || !send_protobuf_message(ssl_ctx, msg_data)) {
                session_state = SessionState::BLOCK_REQ__FAILED;
                return;
            }
            break;
            
        case SessionState::BLOCK_REQ__SEND_IN_USE:
            reply_msg.set_reply(seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_IN_USE);
            if (!reply_msg.SerializeToString(&msg_data) || !send_protobuf_message(ssl_ctx, msg_data)) {
                session_state = SessionState::BLOCK_REQ__FAILED;
                return;
            }
            break;
            
        case SessionState::BLOCK_REQ__SEND_GRANTED:
            reply_msg.set_reply(seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_GRANTED);
            if (!reply_msg.SerializeToString(&msg_data) || !send_protobuf_message(ssl_ctx, msg_data)) {
                close(reserve_sockfd);
                session_state = SessionState::BLOCK_REQ__FAILED;
                return;
            }
            
            assert(session_state == SessionState::BLOCK_REQ__SEND_GRANTED);
            session_state = SessionState::BLOCK_REQ__RECV_CONFIRMATION;
            break;
            
        default:
            throw std::logic_error("Inconsistent server state");
    }
    
    if (session_state == SessionState::BLOCK_REQ__RECV_CONFIRMATION) {
        std::vector<unsigned char> buf(128);
        auto opt_msg_len = receive_protobuf_message(ssl_ctx, buf);
        seng_proto::ListenStartConfirm confirm_msg;
        
        // check whether we successfully received the confirmation message
        if (!opt_msg_len || !confirm_msg.ParseFromArray(buf.data(), *opt_msg_len)) {
            session_state = SessionState::BLOCK_REQ__FAILED;
            close(reserve_sockfd);
            return;
        }
        
        assert(session_state == SessionState::BLOCK_REQ__RECV_CONFIRMATION);
        if (confirm_msg.reply() == seng_proto::ListenStartConfirm_Replies::ListenStartConfirm_Replies_FAILED) {
            session_state = SessionState::BLOCK_REQ__UNDO_RESERVE;
        } else if (confirm_msg.reply() == seng_proto::ListenStartConfirm_Replies::ListenStartConfirm_Replies_NOW_LISTENING) {
            session_state = SessionState::BLOCK_REQ__BLOCK;
        }
    }
    
    if (session_state == SessionState::BLOCK_REQ__UNDO_RESERVE) {
        std::cout << "Unblocking reserved (port, proto) as Enclave seems to have failed enabling listen mode" << std::endl;
        close(reserve_sockfd);
        
    } else if (session_state == SessionState::BLOCK_REQ__BLOCK) {
        std::cout << "Permanently blocking the requested (port, proto) as Enclave has started listening" << std::endl;
        
        BlockInfo bi {
            .sockfd = reserve_sockfd,
            .port = static_cast<in_port_t>(block_msg.port()),
            .proto = static_cast<uint8_t>(block_msg.proto()),
            .mr_enclave = {},
            .mr_signer = {},
        };
        
        // copy the MRENCLAVE and MRSIGNER measurements
        try {
            auto ret = block_msg.mr_enclave().copy((char *)bi.mr_enclave.m, SGX_HASH_SIZE);
            assert(ret == SGX_HASH_SIZE);
            
            ret = block_msg.mr_signer().copy((char *)bi.mr_signer.m, SGX_HASH_SIZE);
            assert(ret == SGX_HASH_SIZE);
        } catch (std::exception &e) {
            session_state = SessionState::BLOCK_REQ__FAILED;
            close(reserve_sockfd);
            std::cerr << e.what() << std::endl;
            return;
        }
        
        if (block_msg.proto() == IPPROTO_TCP) {
            tcp_block_map[block_msg.port()] = bi;
        } else {
            udp_block_map[block_msg.port()] = bi;
        }
    }
    
    assert(session_state == SessionState::BLOCK_REQ__SEND_DENIED  ||
           session_state == SessionState::BLOCK_REQ__SEND_IN_USE  ||
           session_state == SessionState::BLOCK_REQ__UNDO_RESERVE ||
           session_state == SessionState::BLOCK_REQ__BLOCK);
    
    session_state = SessionState::BLOCK_REQ__SUCCESS;
}

void handle_close_request(mbedtls_ssl_context *ssl_ctx, SessionState &session_state,
                         const seng_proto::CliBlockerMsg_CloseNotify &close_msg) {
    assert(session_state == SessionState::CLOSE_REQ__START_PROCESSING);
    std::cout << close_msg.DebugString() << std::endl;
    
    if (!is_supported_protocol(close_msg.proto())) {
        assert(session_state == SessionState::CLOSE_REQ__START_PROCESSING);
        session_state = SessionState::CLOSE_REQ__FAILED;
        std::cerr << "Only TCP or UDP ports can be blocked" << std::endl;
        return;
    }
    
    if (!is_in_port_range(close_msg.port())) {
        assert(session_state == SessionState::CLOSE_REQ__START_PROCESSING);
        session_state = SessionState::CLOSE_REQ__FAILED;
        std::cerr << "Port is out of 16bit max. range" << std::endl;
        return;
    }
    
    assert( session_state == SessionState::CLOSE_REQ__START_PROCESSING );
    session_state = SessionState::CLOSE_REQ__CHECK_WHETHER_BLOCKED;
    
    // check whether we were blocking the port-proto combination
    if (close_msg.proto() == IPPROTO_TCP && tcp_block_map.count(close_msg.proto()) > 0 ||
        close_msg.proto() == IPPROTO_UDP && udp_block_map.count(close_msg.proto()) > 0) {
        // yes
        assert(session_state == SessionState::CLOSE_REQ__CHECK_WHETHER_BLOCKED);
        session_state = SessionState::CLOSE_REQ__UNBLOCK;
        
        BlockInfo bi;
        if (close_msg.proto() == IPPROTO_TCP) {
            bi = tcp_block_map.at(close_msg.port());
            tcp_block_map.erase(close_msg.port());
        } else {
            bi = udp_block_map.at(close_msg.port());
            udp_block_map.erase(close_msg.port());
        }
     
        int ret = close(bi.sockfd);
        assert(ret == 0);
        std::cout << "Stopped Blocking /" << (bi.proto == IPPROTO_TCP ? "tcp" : "udp") << ":" <<  bi.port << std::endl;
        std::cout << "It has been blocked for" << std::endl
        
        << "MR ENCLAVE: ";
        for (int i=0; i<sizeof(bi.mr_enclave.m); i++) {
            printf("%02x", bi.mr_enclave.m[i]);
        }
        std::cout << std::endl
        << "MR SIGNER: ";
        for (int i=0; i<sizeof(bi.mr_signer.m); i++) {
            printf("%02x", bi.mr_signer.m[i]);
        }
        std::cout << std::endl << std::endl;
        
        assert(session_state == SessionState::CLOSE_REQ__UNBLOCK);
            session_state = SessionState::CLOSE_REQ__SEND_NOW_UNLBOCKED;
        
    } else {
        // no
        assert(session_state == SessionState::CLOSE_REQ__CHECK_WHETHER_BLOCKED);
        session_state = SessionState::CLOSE_REQ__SEND_WAS_NOT_BLOCKED;
        // Is this still the case?
        std::cerr << "[CAUTION] The notified (port, proto) was not being blocked. This situation might have been caused by inconsistent state between Enclave, NGW and CliSB." << std::endl;
        // was the FD srv flag cleaned on close/fail?
        // was the NGW state correctly updated on close?
        // did NGW double notify bcs. of some still ESTALBISHED connections to the Enclave?
    }
    
    assert(session_state == SessionState::CLOSE_REQ__SEND_NOW_UNLBOCKED ||
           session_state == SessionState::CLOSE_REQ__SEND_WAS_NOT_BLOCKED);
    
    seng_proto::CliBlockerReply reply_msg;
    std::string msg_data;
    switch (session_state) {
        case SessionState::CLOSE_REQ__SEND_NOW_UNLBOCKED:
            reply_msg.set_reply(seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_NOW_UNLBOCKED);
            if (!reply_msg.SerializeToString(&msg_data) || !send_protobuf_message(ssl_ctx, msg_data)) {
                session_state = SessionState::CLOSE_REQ__FAILED;
                return;
            }
            break;
            
        case SessionState::CLOSE_REQ__SEND_WAS_NOT_BLOCKED:
            reply_msg.set_reply(seng_proto::CliBlockerReply_Replies::CliBlockerReply_Replies_WAS_NOT_BLOCKED);
            if (!reply_msg.SerializeToString(&msg_data) || !send_protobuf_message(ssl_ctx, msg_data)) {
                session_state = SessionState::CLOSE_REQ__FAILED;
                return;
            }
            break;

        default:
            throw std::logic_error("Inconsistent server state");
    }
    
    session_state = SessionState::CLOSE_REQ__SUCCESS;
}

optional<uint32_t>
receive_protobuf_message(mbedtls_ssl_context *ssl_ctx, std::vector<unsigned char> &buf) {
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

bool send_protobuf_message(mbedtls_ssl_context *ssl_ctx, std::string &msg) {
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

bool is_supported_protocol(uint8_t proto) {
    // Check that protocol is either TCP or UDP
    return proto == IPPROTO_TCP || proto == IPPROTO_UDP;
}

bool is_in_port_range(in_port_t port) {
    // Check that port number is not out of range
    return port <= std::numeric_limits<uint16_t>::max();
}

void cleanup_block_sockets() {
    std::cout << "Cleaning up BlockInfo sockets" << std::endl;
    for ( const auto &kv : tcp_block_map ) close(kv.second.sockfd);
    for ( const auto &kv : udp_block_map ) close(kv.second.sockfd);
    tcp_block_map.clear();
    udp_block_map.clear();
}
