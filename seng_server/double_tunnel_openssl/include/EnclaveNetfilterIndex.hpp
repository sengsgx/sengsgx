#ifndef SENG_ENCNETFLTIDX_HPP
#define SENG_ENCNETFLTIDX_HPP

#include "EncIdxBase.hpp"

#include <vector>
#include <memory>
#include <map>
#include <bitset>

#include <sgx_quote.h>

#include <mutex>

#include <netinet/in.h>

#include <experimental/optional>
//#include <optional>

#include <sqlite3.h>


using namespace std::experimental;


namespace seng {
    class EnclaveNetfilterIndex: public EnclaveIndexBase {  
    private:
        //! connection to database
        sqlite3 *db_con;
        
        //! connect to database
        void init_database(const char *path_to_db);
        void init_netfilter_connection(void);

        void cleanup_netfilter_connection(void);

        bool add_enclave_to_module(u_int32_t enclave_ip, sgx_report_body_t *report,
            u_int32_t host_ip);
        
        in_addr_t get_free_internal_ip(in_addr_t enc_subnet) override;
        
        bool release_enclave_ip(in_addr_t enclave_ip) override;

        unsigned char next_potential_client_number;
        std::bitset<256> client_num_bitset;        

    public:
        const in_addr_t base_subnet;
        const in_addr_t netmask, gateway;

        bool is_whitelisted_app(sgx_report_body_t *report) override;
        
        optional<NetworkConfig> get_enclave_ip(sgx_report_body_t *report, in_addr_t host_ip) override;
        
        EnclaveNetfilterIndex(const char *path_to_db);
        ~EnclaveNetfilterIndex();
        
        // avoid copy errors
        EnclaveNetfilterIndex(EnclaveNetfilterIndex &) = delete;
        EnclaveNetfilterIndex& operator=(EnclaveNetfilterIndex &) = delete;
        EnclaveNetfilterIndex(EnclaveNetfilterIndex &&) noexcept = delete;
        
        void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) override;
    };
}

#endif /* SENG_ENCNETFLTIDX_HPP */
