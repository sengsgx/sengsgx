#ifndef SENG_PACKETFORWARDER_HPP
#define SENG_PACKETFORWARDER_HPP

#include "EnclaveIndex_adapted.hpp"

#include <vector>
#include <memory>

#include <sys/types.h> // ssize_t

#include <uv.h>


namespace seng {
    struct PacketForwarder {
        PacketForwarder(std::shared_ptr<EnclaveIndex> &);
        ~PacketForwarder();

        ssize_t send_ip_packet(std::unique_ptr<unsigned char[]> ip_packet_up, int len);
        ssize_t recv_ip_packet(unsigned char *ip_buffer, int len);

        int tunnel_fd;
        int tunnel_mtu;

        uv_poll_t event_loop_fd_ctx;
        
        std::shared_ptr<EnclaveIndex> enclave_idx_sp;
        
        void attach_to_tunnel_interface();
        void detach_from_tunnel_interface();
        
        void add_to_event_loop(uv_loop_t *loop);
        
        //! UV poll callback
        static void trmpln_incoming_reply_ip_packet(uv_poll_t* handle, int status, int events);
        void incoming_reply_ip_packet(int status);
        void dispatch_reply_packet_to_enclave_tunnel(std::unique_ptr<unsigned char[]>,
                                                     ssize_t, in_addr_t);
    };
}

#endif /* SENG_PACKETFORWARDER_HPP */
