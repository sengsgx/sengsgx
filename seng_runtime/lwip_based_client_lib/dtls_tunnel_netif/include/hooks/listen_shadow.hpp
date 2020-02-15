#ifndef SENG_LISTEN_SHADOW_HPP
#define SENG_LISTEN_SHADOW_HPP

#include "HookCommons.hpp"
#include <bitset>

#include <vector>
#include <string>
#include <experimental/optional>

using namespace std::experimental;

namespace seng {
    int request_listen_shadowing(int srv_fd, int backlog);
    
    optional<uint32_t> receive_protobuf_message(int sockfd, std::vector<unsigned char> &buf);
    bool send_protobuf_message(int sockfd, std::string &msg);
    
    static std::bitset< MAX_LWIP_SOCKETS > server_fds_bitset;
    void notify_listen_close(int srv_fd);
}

#endif /* SENG_LISTEN_SHADOW_HPP */
