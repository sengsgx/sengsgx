#include "PacketForwarder_adapted.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>
#include <string>
#include <stdexcept>

#include <cerrno>
#include <cstring>
#include <cassert>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <netinet/in.h> // otherwise if.h misses 'struct sockaddr'

// Linux specific
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/ip.h>

//#define DEBUG_FORWARDER


namespace seng {
    PacketForwarder::PacketForwarder(std::shared_ptr<EnclaveIndex> &enc_idx_sp) :
    enclave_idx_sp(enc_idx_sp) {
        attach_to_tunnel_interface();
    }
    PacketForwarder::~PacketForwarder() {
        detach_from_tunnel_interface();
    }

    ssize_t PacketForwarder::send_ip_packet(std::unique_ptr<unsigned char[]> ip_packet_up, int len) {
        if (len > tunnel_mtu)
            throw std::runtime_error("IP Packet is larger than TUN interface MTU");
        return write(tunnel_fd, ip_packet_up.get(), len);
    }
    
    ssize_t PacketForwarder::recv_ip_packet(unsigned char *ip_buffer, int len) {
        if(len < tunnel_mtu)
            throw std::runtime_error("Recv buffer < MTU, s.t. packet might not fit");
        
        // TODO: don't write to internal buffer of vector directly w/o check
        //      ~> packet_buffer.resize(read_bytes)
        return read(tunnel_fd, ip_buffer, len);
    }
    
    void PacketForwarder::attach_to_tunnel_interface() {
        const char *tuntap_device = "/dev/net/tun";
        const char *tun_name = "tunSX";
        
        // open the tuntap device / interface to the tun LKM
        tunnel_fd = open(tuntap_device, O_RDWR);
        if (tunnel_fd < 0)
            throw std::runtime_error(std::string("Failed to open TUNTAP device interface; ")
                                     + std::strerror(errno));
        
        // perform ioctl() to create new / attach to existing TUN interface
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);
        ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
        if(ioctl(tunnel_fd, TUNSETIFF, (void *) &ifr) < 0) {
            close(tunnel_fd);
            throw std::runtime_error(std::string("Failed to create/attach to TUN interface; ")
                                     + std::strerror(errno));
        }
        
        // get MTU of TUN interface (applying ioctl() on tunnel_fd always failed)
        int tmp_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if(ioctl(tmp_fd, SIOCGIFMTU, (void *) &ifr) < 0) {
            close(tunnel_fd);
            close(tmp_fd);
            throw std::runtime_error(std::string("Failed to get MTU of TUN interface; ")
                                     + std::strerror(errno));
        }
        tunnel_mtu = ifr.ifr_mtu;
        close(tmp_fd);
        
        std::cout << "MTU: " << tunnel_mtu << std::endl;
    }
    
    void PacketForwarder::detach_from_tunnel_interface() {
        close(tunnel_fd);
    }
    
    void PacketForwarder::add_to_event_loop(uv_loop_t *loop) {
        // sets non-blocking mode
        int ret = uv_poll_init(loop, &event_loop_fd_ctx, tunnel_fd);
        assert(ret == 0);
        event_loop_fd_ctx.data = (void *) this;
        
        // check that it is indeed in non-blocking mode
        assert ( (fcntl(tunnel_fd, F_GETFL, 0) & O_NONBLOCK) != 0 );

        // NOTE: could also watch for writeable if we add a pckt queue
        ret = uv_poll_start(&event_loop_fd_ctx, UV_READABLE, trmpln_incoming_reply_ip_packet);
        assert(ret == 0);
        if (ret != 0) throw std::runtime_error("Adding PacketForwarder to event loop failed");
    }
    
    void PacketForwarder::trmpln_incoming_reply_ip_packet(uv_poll_t* handle, int status, int events) {
        assert(handle->data != nullptr);
        assert(events == UV_READABLE);
        ((PacketForwarder *)handle->data)->incoming_reply_ip_packet(status);
    }
    void PacketForwarder::incoming_reply_ip_packet(int status) {
        // read IP packet
        auto ip_pckt_up = std::make_unique<unsigned char[]>(tunnel_mtu);
        auto ret = recv_ip_packet(ip_pckt_up.get(), tunnel_mtu);
        if(ret < 0) {
            if (errno == EAGAIN) {
                std::cerr << "Reading attempt on TUN returned EAGAIN (non-blocking mode) which is strange after read notify" << std::endl;
            }
            throw std::runtime_error("Failed to receive relpy IP packet in PacketForwarder");
        }
        if(ret == 0) throw std::logic_error("External interface of PacketForwarder seems to have been closed? TODO");
        
        assert(ret >= 20 && ret <= tunnel_mtu); // [min. ip_hdr, mtu]
        
        // parse dstIP
        in_addr_t dst_ip { ((struct iphdr *)ip_pckt_up.get())->daddr };
        
        // get_transport_layer_port_number(ip_pckt_up.get(), ret);
        
        dispatch_reply_packet_to_enclave_tunnel(std::move(ip_pckt_up), ret, dst_ip);
    }
    
    void PacketForwarder::dispatch_reply_packet_to_enclave_tunnel(std::unique_ptr<unsigned char[]> ip_pckt_up,
                                                                  ssize_t pckt_len, in_addr_t dst_ip) {

        // lookup active, registered TunnelToEnclave object
        TunnelToEnclaveOpenSSL * target_tte = enclave_idx_sp->get_enclave_handle_by_ip(dst_ip);
        if (target_tte == nullptr) {
#ifdef DEBUG_FORWARDER
            // This can happen quite often on connection shutdown/close due to retransmissions
            // of non-delivered FIN/ACK messages.
            std::cerr << "No active Enclave with internal IP matching the dstIP: " << inet_ntoa({dst_ip}) << std::endl;
#endif
            return;
        }
        
        // request send of packet
        target_tte->tunnel_reply_to_enclave(std::move(ip_pckt_up), pckt_len);
    }
}
