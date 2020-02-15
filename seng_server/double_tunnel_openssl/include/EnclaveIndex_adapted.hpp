#ifndef SENG_ENCLAVEINDEX_HPP
#define SENG_ENCLAVEINDEX_HPP

#include <vector>
#include <memory>
#include <map>
#include <bitset>

#include <sgx_quote.h>

#include <mutex>

#include <netinet/in.h>

#include "enc_srv_socks/ShadowRule.hpp"

#include <experimental/optional>

using namespace std::experimental;


namespace seng {
    struct TunnelToEnclaveOpenSSL;
    
    class EnclaveIndex {
    public:
        // avoid copy errors
        EnclaveIndex(EnclaveIndex &) = delete;
        EnclaveIndex& operator=(EnclaveIndex &) = delete;
        EnclaveIndex(EnclaveIndex &&) noexcept = delete;
        
        // currently 192.168.178.0/24, where client .1 is tunFA/NGW (0 reserved, 255 is broadcast)
        EnclaveIndex();
        ~EnclaveIndex();

        // TODO: add SGX report as parameter and choose IP from subnetwork matching policy
        in_addr_t get_free_internal_ip();
        
        void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip);
        
        TunnelToEnclaveOpenSSL *get_enclave_handle_by_ip(in_addr_t enclave_ip);
        
        void mark_enclave_tunnel_closed(in_addr_t enclave_ip);
        void cleanup_closed_tunnels();

        bool is_active_enclave(in_addr_t enclave_ip);
        optional<in_addr_t> get_ip_of_enclaves_tunnel_host(in_addr_t enclave_ip);
        sgx_quote_t get_enclave_quote(in_addr_t enclave_ip);
        
        const in_addr_t base_subnet;
        const in_addr_t netmask, gateway;
        
        bool is_already_shadowed(in_port_t port, uint8_t proto, in_addr_t client_ip);
        //! If the rule is not already enabled, this method will attempt to enable it on the process
        bool commit_shadow_rule(ShadowRule rule);
        optional<ShadowRule> get_shadow_rule(int handle, in_addr_t enclave_ip);
        
    private:
        std::mutex enclave_idx_guard;
        
        std::vector<std::unique_ptr<TunnelToEnclaveOpenSSL>> active_enclaves;
        //! mapping from internal(!) Enclave IP to TunnelToEnclave object
        std::map<in_addr_t, TunnelToEnclaveOpenSSL *> ip_to_enclave_idx;
        
        std::vector<std::unique_ptr<TunnelToEnclaveOpenSSL>> disconnected_enclaves;
        
        unsigned char next_potential_client_number;
        
        //! mapping from untrusted CliIP (used for tunnel) to Shadow rule list
        std::map<in_addr_t, std::vector<ShadowRule>> cli_ip_to_rules;
        
        std::bitset<256> client_num_bitset;
    };
}

#endif /* SENG_ENCLAVEINDEX_HPP */
