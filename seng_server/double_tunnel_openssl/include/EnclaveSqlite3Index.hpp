#ifndef SENG_ENCSQLTIDX_HPP
#define SENG_ENCSQLTIDX_HPP

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
    // all in network byte-order
    struct SubnetMetadata {
        SubnetMetadata(in_addr_t base_subnet, in_addr_t base_submask, in_addr_t base_gateway);
        //! base subnet address
        const in_addr_t subnet;
        //! netmask
        const in_addr_t submask;
        //! number of IPs (-0,-broadcast)
        const int subnet_size;
        //! gateway for this subnet
        const in_addr_t gateway;
        //! next index tried to be assigned (IP-1)
        unsigned int next_tested_ip_index;
        //! bitset for used/unused IPs (>= subnet_size entries)
        std::vector<bool> client_num_bitset;
    };

    class EnclaveSqliteIndex: public EnclaveIndexBase {
    protected:
        //! mapping from enc subnet to metadata
        std::map<in_addr_t, SubnetMetadata> encsub_to_info;
                
    private:
        //! connection to database
        sqlite3 *db_con;
        
        //! connect to database
        void init_database(const char *path_to_db);
        //! query defined enclave subnetworks and init ensub_to_info
        void cache_defined_subnets();
        
        in_addr_t get_free_internal_ip(in_addr_t enc_subnet) override;
        
        bool release_enclave_ip(in_addr_t enclave_ip) override;
        
        in_addr_t get_gateway(in_addr_t enc_subnet);
        in_addr_t get_submask(in_addr_t enc_subnet);

    public:
        bool is_allowlisted_app(sgx_report_body_t *report) override;
        
        optional<NetworkConfig> get_enclave_ip(sgx_report_body_t *report, in_addr_t host_ip) override;
        
        EnclaveSqliteIndex(const char *path_to_db);
        ~EnclaveSqliteIndex();
        
        // avoid copy errors
        EnclaveSqliteIndex(EnclaveSqliteIndex &) = delete;
        EnclaveSqliteIndex& operator=(EnclaveSqliteIndex &) = delete;
        EnclaveSqliteIndex(EnclaveSqliteIndex &&) noexcept = delete;
        
        void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) override;
    };
}

#endif /* SENG_ENCSQLTIDX_HPP */
