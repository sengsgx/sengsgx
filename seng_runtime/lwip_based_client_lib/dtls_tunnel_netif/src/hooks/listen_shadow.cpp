#include "hooks/listen_shadow.hpp"
#include "DT_OnLoadSENGStarter_OpenSSL.hpp"

#include <iostream>

#include <lwip/sockets.h>
#include <lwip/netifapi.h>
#include <lwip/inet.h>

#include <lwip/errno.h>

#include "seng.pb.h"


namespace seng {
    // TODO: use the dynamically received GW IP instead
    const char *shadow_srv_ip {"192.168.28.1"};


    // copied from ClientSocketShadower.cpp
    optional<uint32_t>
    receive_protobuf_message(int sockfd, std::vector<unsigned char> &buf) {
        // must be able to receive the message length
        if (buf.size() < 4) return {};
        ssize_t recv_len {};
        // receive length of message
        if( (recv_len = lwip_recv(sockfd, buf.data(), 4, MSG_WAITALL)) < 0) {
            perror(nullptr);
            return {};
        }
        if (recv_len != 4) return {};
        
        uint32_t protobuf_len { * ((uint32_t *)buf.data()) };
        // check whether buffer can receive whole message
        if( buf.size() < protobuf_len ) return {};
        
        // receive the actual message
        if( (recv_len = lwip_recv(sockfd, buf.data(), protobuf_len, MSG_WAITALL)) < 0) {
            perror(nullptr);
            return {};
        }
        if (recv_len != protobuf_len) return {};
        
        return make_optional(protobuf_len);
    }
    
    // copied from ClientSocketShadower.cpp
    bool send_protobuf_message(int sockfd, std::string &msg) {
        // Send message length first
        uint32_t msg_len = msg.size();
        ssize_t missing_bytes { 4 };
        
        ssize_t sent_bytes { 0 };
        auto p = (unsigned char *)&msg_len;
        while (missing_bytes > 0) {
            if( (sent_bytes = lwip_send(sockfd, p, missing_bytes, 0)) < 0) {
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
            if( (sent_bytes = lwip_send(sockfd, p, missing_bytes, 0)) < 0) {
                perror(nullptr);
                return false;
            }
            missing_bytes -= sent_bytes;
            p += sent_bytes;
        }
        
        return true;
    }
    
    int fail_listen(optional<int> fd) {
        if(fd) lwip_close(*fd);
        /*
         * Why EADDRINUSE?:
         *  If two sockets bind() to the same address => EADDRINUSE
         *
         *  If two sockets set SO_REUSADDR, they can successfully bind() to the same address;
         *  The 1st can now successfully call listen() on it, but the 2nd will get the
         *  EADDRINUSE error;
         *
         *  So this error code should reflect the situation best as in most cases
         *  the DENIAL will be due to a (port, proto) being already shadowed, or
         *  already blocked by the untrusted client;
         &
         *  The case where the Client denies it by policy would be better reflected
         *  by a EPERM, but this does not officially exist for listen();
         *  connect() and accept() have it;
         *
         *  But if we would move to accept(), we would still need to add a forward
         *  rule on listen() to allow new connection requests to reach the Enclave in
         *  the first place; and then accept() would have to ask for permission for
         *  each connection;
         *  But at the moment we want to allow or deny connections for an Enclave
         *  in an "all or none" sense; but more fine-grained control on which external
         *  host are allowed to connect could be added later on; probably also w/o
         *  NGW server interaction, completely on GW-Firewall level.
         */
        errno = EADDRINUSE;
        return -1;
    }
    
    int request_listen_shadowing(int srv_fd, int backlog) {
        // check if this might be a duplicate listen() call just for changing backlog
        if( server_fds_bitset.test( srv_fd - LWIP_SOCKET_OFFSET ) ) {
#ifdef DEBUG_PRINT
            std::cout << "requested socket has already been marked as listener (only call for changing backlog? or bug bcs. previous socket was not explicitly closed?)" << std::endl;
#endif
            return lwip_listen(srv_fd, backlog);
        }
        
        struct sockaddr_in bound_addr;
        socklen_t addr_len { sizeof(bound_addr) };
        
        if(lwip_getsockname(srv_fd, (struct sockaddr *)&bound_addr, &addr_len) < 0) {
#ifdef DEBUG_PRINT
            std::cout << "lwip_getsockname() returned < 0 during listen mechanism" << std::endl;
#endif
            return fail_listen({});
        }
        // unbound
        if(bound_addr.sin_port == 0) {
#ifdef DEBUG_PRINT
            std::cout << "bound.addr.sin_port == 0 during listen mechanism" << std::endl;
#endif
            return fail_listen({});
        }
        
        int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) { return fail_listen({}); }
        
        struct sockaddr_in shdw_srv {
            .sin_family = AF_INET,
            .sin_port = lwip_htons(2409),
            //.sin_addr = { tunnel_netif.gw.addr },
        };
        inet_aton(shadow_srv_ip, &shdw_srv.sin_addr);
        
        if (lwip_connect(fd, (struct sockaddr *)&shdw_srv, sizeof(shdw_srv)) < 0) {
#ifdef DEBUG_PRINT
            std::cout << "Failed lwip listen mechanism, bcs. connection to Shadow Server failed" << std::endl;
#endif
            return fail_listen({fd});
        }
        
        try {
            uint32_t handle = srv_fd;
            
            seng_proto::ShadowSrvMsg wrap_msg;
            auto msg = new seng_proto::ShadowSrvMsg_RequestCliSockShadowing();
            msg->set_port(bound_addr.sin_port);
            /* TODO:
             * note that we currently only support TCP Servers at Enclave side;
             * UDP requires hooking bind(), and all send/receive functions to
             * identify "UDP Server" sockets, as no listen/accept exists for UDP
             */
            msg->set_proto(IPPROTO_TCP);
            msg->set_handle(handle);
            wrap_msg.set_allocated_reqshadow(msg);
            
            std::string msg_data;
            if (!wrap_msg.SerializeToString(&msg_data)) {
                lwip_close(fd);
                return false;
            }
            if( !send_protobuf_message(fd, msg_data) ) {
#ifdef DEBUG_PRINT
                std::cout << "listen mech.: failed to send protobuf message" << std::endl;
#endif
                return fail_listen({fd});
            }
            
            std::vector<unsigned char> buf(128);
            optional<uint32_t> opt_msg_len = receive_protobuf_message(fd, buf);
            if( !opt_msg_len ) {
#ifdef DEBUG_PRINT
                std::cout << "listen mech.: failed to receive length of protobuf message" << std::endl;
#endif
                return fail_listen({fd});
            }
            
            seng_proto::ShadowReqReply reply_msg;
            if( !reply_msg.ParseFromArray(buf.data(), *opt_msg_len) ) {
#ifdef DEBUG_PRINT
                std::cout << "listen mech.: failed to receive actual protobuf message" << std::endl;
#endif
                return fail_listen({fd});
            }
            if( reply_msg.reply() == seng_proto::ShadowReqReply_Replies::ShadowReqReply_Replies_DENIED ) {
#ifdef DEBUG_PRINT
                std::cout << "listen mech.: Shadow Request got DENIED" << std::endl;
#endif
                return fail_listen({fd});
            }

            assert( reply_msg.reply() == seng_proto::ShadowReqReply_Replies_GRANTED );
            int ret = lwip_listen(srv_fd, backlog);
            auto safe = errno;
            
            seng_proto::ListenStartConfirm confirm_msg;
            if( ret < 0 ) {
                confirm_msg.set_reply(seng_proto::ListenStartConfirm_Replies::ListenStartConfirm_Replies_FAILED);
            } else {
                confirm_msg.set_reply(seng_proto::ListenStartConfirm_Replies::ListenStartConfirm_Replies_NOW_LISTENING);
            }
            if(( !confirm_msg.SerializeToString(&msg_data) || !send_protobuf_message(fd, msg_data)) ) {
                std::cerr << "Something went wrong when sending the confirm message" << std::endl;
                // TODO: this case is ugly, because lwip_listen() has already been successful, i.e. we might have inconsistent state -> should later move into lwIP itself
                if (ret >= 0) {
                    std::cerr << "Warning, corrupt state; bcs. lwip_listen() was successful, but we couldn't report that back to the NGW" << std::endl;
                    return fail_listen({fd});
                }
                std::cerr.flush();
            }
            
            // mark srv_fd as server fd
            if (ret == 0) server_fds_bitset.set( srv_fd - LWIP_SOCKET_OFFSET );
            
#ifdef DEBUG_PRINT
            std::cout << "listen mech.: SUCCESS" << std::endl;
#endif
            
            lwip_close(fd);
            errno = safe;
            return ret;
            
        } catch (...) {
            std::cerr << "caught exception" << std::endl;
            std::cerr.flush();
            return fail_listen({fd});
        }
    }
    
    void notify_listen_close(int srv_fd) {
        // not a server fd
        if( !server_fds_bitset.test( srv_fd - LWIP_SOCKET_OFFSET ) ) return;
        // unset bit
        server_fds_bitset.reset( srv_fd - LWIP_SOCKET_OFFSET );
        
        int fd = lwip_socket(AF_INET, SOCK_STREAM, 0);
        if(fd < 0) return;
        
        struct sockaddr_in shdw_srv {
            .sin_family = AF_INET,
            .sin_port = lwip_htons(2409),
            //.sin_addr = { tunnel_netif.gw.addr },
        };
        inet_aton(shadow_srv_ip, &shdw_srv.sin_addr);
        
#ifdef DEBUG_PRINT
        std::cout << "listen mech.: Trying to notify close" << std::endl;
#endif
        
        if (lwip_connect(fd, (struct sockaddr *)&shdw_srv, sizeof(shdw_srv)) < 0) {
#ifdef DEBUG_PRINT
            std::cout << "listen mech.: FAILED notify close" << std::endl;
#endif
            lwip_close(fd);
            return;
        }
        
        // Craft and send Close Notify Message
        seng_proto::ShadowSrvMsg wrap_msg;
        auto close_msg = new seng_proto::ShadowSrvMsg_NotifyAboutClose();
        close_msg->set_handle(srv_fd);
        wrap_msg.set_allocated_closenotify(close_msg);
        
        std::string data;
        if( wrap_msg.SerializeToString(&data) ) {
            send_protobuf_message(fd, data);
        }
        
#ifdef DEBUG_PRINT
        std::cout << "listen mech.: Successful notify close" << std::endl;
#endif
        lwip_close(fd);
        return;
    }
}
