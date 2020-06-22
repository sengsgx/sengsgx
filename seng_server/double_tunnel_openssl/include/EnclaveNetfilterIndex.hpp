#ifndef SENG_ENCNETFLTIDX_HPP
#define SENG_ENCNETFLTIDX_HPP

#include "EnclaveIndex_adapted.hpp"

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
    class EnclaveNetfilterIndex: public EnclaveIndex {
    private:
        //! connection to database
        sqlite3 *db_con;
        
        //! connect to database
        void init_database(const char *path_to_db);
        void init_netfilter_connection(void);

        void cleanup_netfilter_connection(void);

        bool add_enclave_to_module(uint32_t enclave_ip, uint8_t mr_enclave[], uint32_t host_ip);
        bool remove_enclave_from_module(uint32_t enclave_ip);

        std::vector<std::string> query_categories(uint8_t mr_enclave[]);

    public:
        EnclaveNetfilterIndex(const char *path_to_db);
        ~EnclaveNetfilterIndex();
        
        // avoid copy errors
        EnclaveNetfilterIndex(EnclaveNetfilterIndex &) = delete;
        EnclaveNetfilterIndex& operator=(EnclaveNetfilterIndex &) = delete;
        EnclaveNetfilterIndex(EnclaveNetfilterIndex &&) noexcept = delete;
        
        void add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) override;
        void mark_enclave_tunnel_closed(in_addr_t enclave_ip) override;
    };
}

#endif /* SENG_ENCNETFLTIDX_HPP */
