#ifndef SENG_ENCLAVEINDEX_HPP
#define SENG_ENCLAVEINDEX_HPP

#include "EncIdxBase.hpp"

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
    
    class EnclaveIndex : public EnclaveIndexBase {
    public:
        // avoid copy errors
        EnclaveIndex(EnclaveIndex &) = delete;
        EnclaveIndex& operator=(EnclaveIndex &) = delete;
        EnclaveIndex(EnclaveIndex &&) noexcept = delete;
        
        // currently 192.168.178.0/24, where client .1 is tunFA/NGW (0 reserved, 255 is broadcast)
        EnclaveIndex();
        ~EnclaveIndex();

        bool release_enclave_ip(in_addr_t enclave_ip) override;
        bool is_allowlisted_app(sgx_report_body_t *report) override;
        optional<NetworkConfig> get_enclave_ip(sgx_report_body_t *report, in_addr_t host_ip) override;
        in_addr_t get_free_internal_ip(in_addr_t enc_subnet) override;
        
        void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) override;
        
        const in_addr_t base_subnet;
        const in_addr_t netmask, gateway;

    private:
        unsigned char next_potential_client_number;
        std::bitset<256> client_num_bitset;
    };
}

#endif /* SENG_ENCLAVEINDEX_HPP */
