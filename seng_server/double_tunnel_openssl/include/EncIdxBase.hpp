#ifndef SENG_ENCIDXBASE_HPP
#define SENG_ENCIDXBASE_HPP

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
//#include <optional>


namespace seng {
    struct TunnelToEnclaveOpenSSL;
    
    struct NetworkConfig {
        in_addr_t ip;
        in_addr_t submask;
        in_addr_t gateway;
    };

    class EnclaveIndexBase {
    protected:
        //! mapping from enc IP to tunnel
        std::map<in_addr_t, TunnelToEnclaveOpenSSL *> ip_to_enclave_idx;
                
        std::vector<std::unique_ptr<TunnelToEnclaveOpenSSL>> active_enclaves;
        
        std::vector<std::unique_ptr<TunnelToEnclaveOpenSSL>> disconnected_enclaves;
        
        //! mapping from untrusted CliIP (used for tunnel) to Shadow rule list
        std::map<in_addr_t, std::vector<ShadowRule>> cli_ip_to_rules;
        
        std::mutex enclave_idx_guard;
        
        virtual bool release_enclave_ip(in_addr_t enclave_ip) = 0;
        
        EnclaveIndexBase();
        ~EnclaveIndexBase();
        
    public:
        TunnelToEnclaveOpenSSL *get_enclave_handle_by_ip(in_addr_t enclave_ip);
        optional<in_addr_t> get_ip_of_enclaves_tunnel_host(in_addr_t enclave_ip);
        sgx_quote_t get_enclave_quote(in_addr_t enclave_ip);
        
        virtual bool is_whitelisted_app(sgx_report_body_t *report) = 0;
        virtual optional<NetworkConfig> get_enclave_ip(sgx_report_body_t *report, in_addr_t host_ip) = 0;

    protected:
        virtual in_addr_t get_free_internal_ip(in_addr_t enc_subnet) = 0;
        
    public:
        virtual void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) = 0;
        
        void mark_enclave_tunnel_closed(in_addr_t enclave_ip);
        void cleanup_closed_tunnels();

        bool is_active_enclave(in_addr_t enclave_ip);
        
        bool is_already_shadowed(in_port_t port, uint8_t proto, in_addr_t client_ip);
        //! If the rule is not already enabled, this method will attempt to enable it on the process
        bool commit_shadow_rule(ShadowRule rule);
        //TODO
        optional<ShadowRule> get_shadow_rule(int handle, in_addr_t enclave_ip);
    };
}

#endif /* SENG_ENCIDXBASE_HPP */
