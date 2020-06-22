#include "EnclaveNetfilterIndex.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>

#include <stdexcept>
#include <algorithm>
#include <cstring>

#include <cassert>

extern "C" {
    #include "seng_netfilter_api.h"
}

//#define DEBUG_ENCIDX


namespace seng {
    static unsigned int get_number_of_set_bytes_ip4(in_addr_t netorder_submask);

    static unsigned int get_number_of_set_bytes_ip4(in_addr_t netorder_submask) {
        unsigned int set_bits {0};
        unsigned int t {ntohl(~netorder_submask)};
        while (t > 0) {
            set_bits++;
            t >>= 1;
        }
        return 32 - set_bits;
    }

    void EnclaveNetfilterIndex::init_netfilter_connection() {
        if (prep_nl_sock() != SQLITE_OK) {
            throw std::runtime_error("Failed to open netlink socket to SENG module (Is the kernel module loaded?)");
        }
        if (enable_allowlist_checks() != EXIT_SUCCESS) {
            cleanup_netfilter_connection();
            throw std::runtime_error("Failed to mark DB as ready");
        }
    }

    void EnclaveNetfilterIndex::cleanup_netfilter_connection() {
        flush_module();
        cleanup_nl_sock();
    }

    std::vector<std::string>
    EnclaveNetfilterIndex::query_categories(sgx_report_body_t *report) {
        sqlite3_stmt *pstmt {nullptr};
        std::vector<std::string> categories {};
           const char *CHECK_IF_WHITELISTED = "SELECT id FROM apps WHERE mr_enclave == ?;";
        const char *QUERY_APP_CATEGORIES = "SELECT categories.name FROM categories JOIN apps ON categories.apps_id == apps.id WHERE apps.mr_enclave == ?;";
        /* CREATE PREPARED STATEMENT */
        int ret = sqlite3_prepare_v2(db_con, QUERY_APP_CATEGORIES, strlen(QUERY_APP_CATEGORIES), &pstmt, nullptr);
        if (ret != SQLITE_OK) {
            std::cerr << "error: " << sqlite3_errmsg(db_con) << std::endl;
            throw std::runtime_error("Failed to query app catgories");
        }
        
        /* BIND VALUES TO PREPARED STATEMENT */
        // TODO: correct memory cleanup?
        ret = sqlite3_bind_blob(pstmt, 1, report->mr_enclave.m, SGX_HASH_SIZE, SQLITE_STATIC);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(pstmt);
            throw std::runtime_error("Failed to bind mr_enclave");
        }
        
        // query all categories for the app
        while((ret = sqlite3_step(pstmt)) == SQLITE_ROW) {
            char *category_name = NULL;
            category_name = (char *)sqlite3_column_text(pstmt, 0);
            // TODO: check for error
            categories.push_back(category_name);
        }

        if (ret != SQLITE_DONE) {
            std::cerr << "Error while querying categories for application" << std::endl;
            categories.clear();
        }

        sqlite3_finalize(pstmt);
        return categories;
    }

    bool EnclaveNetfilterIndex::add_enclave_to_module(u_int32_t enclave_ip, sgx_report_body_t *report,
            u_int32_t host_ip) {

        // Add Enclave IP to netfilter module
        bool success = 0 == add_enclave_ack(enclave_ip, report->mr_enclave.m, host_ip, NULL);

        // Check if there is already an active enclave running the same application
        // NOTE: *enclave_idx_guard already held*
        auto it = std::find_if(active_enclaves.begin(), active_enclaves.end(),
            [report](std::unique_ptr<TunnelToEnclaveOpenSSL> &up)->bool {
                return 0 == memcmp(up->quote.report_body.mr_enclave.m,
                    report->mr_enclave.m, SGX_HASH_SIZE);
            });
        
        // case: found something
        if (it != active_enclaves.end()) return success;

        // Query and add categories
        auto categories = query_categories(report);
        for (std::string &s : categories) {
            std::cout << "Adding category: " << s << std::endl;
            cat_to_app_ack(OP_ADD, report->mr_enclave.m, s.c_str());
        }
        return success;
    }

    bool EnclaveNetfilterIndex::remove_enclave_from_module(u_int32_t enclave_ip) {
        return 0 == remove_enclave_ack(enclave_ip);
    }

    void EnclaveNetfilterIndex::init_database(const char *path_to_db) {
        if (sqlite3_open(path_to_db, &db_con) != SQLITE_OK) {
            throw std::runtime_error("Failed to open db");
            std::cerr << "Failed to open db" << std::endl;
        }
    }

    EnclaveNetfilterIndex::EnclaveNetfilterIndex(const char *path_to_db) :
    EnclaveIndexBase(),
    base_subnet(192 | 168 << 8 | 28 << 16),        // 192.168.28.0/24; Note: BigEndian (net-order)
    netmask(255 | 255 << 8 | 255 << 16 | 0 << 24),  // 255.255.255.0 (/24)
    gateway(base_subnet | 1 << 24),                 // 192.168.28.1
    next_potential_client_number(2), client_num_bitset()
    {
        // block 0, GW IP and broadcast
        client_num_bitset.set(0);
        client_num_bitset.set(1);
        client_num_bitset.set(255);

        // TODO: check that database exists (otherwise creates empty one)
        
        /* connect to the database */
        init_database(path_to_db);

        /* connect to SENG Netfilter kernel module */
        init_netfilter_connection();
    }

    EnclaveNetfilterIndex::~EnclaveNetfilterIndex() {
        // TODO
        sqlite3_close(db_con);
        cleanup_netfilter_connection();
    }
    
    in_addr_t EnclaveNetfilterIndex::get_free_internal_ip(in_addr_t _enc_subnet) {
        (void) _enc_subnet;
        
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        in_addr_t ip {0};
        
        // Check if client number is non-assigned
        if (!client_num_bitset.test(next_potential_client_number)) {
            // unassigned, so can fallthrough
            // fallthrough
            
        // Are all in use?
        } else if (client_num_bitset.all()) {
            throw std::runtime_error("Currently out of interal IP addresses");
            
        // Iterate until we find next free one (there has to be at least 1)
        } else {
            auto success {false};
            for (auto i=(next_potential_client_number+1)%255; i!=next_potential_client_number; i=(i+1)%255) {
                if (!client_num_bitset.test(i)) {
                    // found unused one
                    next_potential_client_number = i;
                    success = true;
                    break;
                }
            }
            if (!success) throw std::runtime_error("Did not find an unused IP although there should be at least one");
        }
        
        ip = base_subnet | next_potential_client_number << 24;
        // [2, 254], i.e. 255 drops to 0
        next_potential_client_number = (next_potential_client_number+1) % 255;
        return ip;
    }
    
    void EnclaveNetfilterIndex::add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);

        // Cli number marked as in use?
        if (client_num_bitset.test(enclave_ip >> 24)) {
            throw std::runtime_error("The IP request for the new Enclave is already marked as in use");
        }

        // add to module
        if (!add_enclave_to_module(enclave_ip, &tte_up->quote.report_body,
            tte_up->untrusted_tunnel_host_ip)) {
            throw std::runtime_error("Failed to add new Enclave to Netfilter module");
        }

        // mark as in use
        client_num_bitset.set(enclave_ip >> 24);
        // add reference
        ip_to_enclave_idx[enclave_ip] = tte_up.get();
        // move to list
        active_enclaves.push_back(std::move(tte_up));
    }
    
    bool EnclaveNetfilterIndex::release_enclave_ip(in_addr_t enclave_ip) {
        auto cli_num = enclave_ip >> 24;
        
        // Valid client number?
        if (2 <= cli_num && cli_num <= 255) {
            client_num_bitset.reset(cli_num);
            // note/todo: Could also remove enclave IP from kernel module here
            return true;
        }
        return false;
    }

    bool EnclaveNetfilterIndex::is_whitelisted_app(sgx_report_body_t *report) {
        bool whitelisted {false};
        sqlite3_stmt *pstmt {nullptr};
        // TODO: additionally check enclave attributes (e.g., debug flag, SVN, ...) and/or mr_signer
        const char *CHECK_IF_WHITELISTED = "SELECT id FROM apps WHERE mr_enclave == ?;";
        /* CREATE PREPARED STATEMENT */
        int ret = sqlite3_prepare_v2(db_con, CHECK_IF_WHITELISTED, strlen(CHECK_IF_WHITELISTED), &pstmt, nullptr);
        if (ret != SQLITE_OK) {
            throw std::runtime_error("Failed to query app whitelist");
        }
        
        /* BIND VALUES TO PREPARED STATEMENT */
        // TODO: correct memory cleanup?
        ret = sqlite3_bind_blob(pstmt, 1, report->mr_enclave.m, SGX_HASH_SIZE, SQLITE_STATIC);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(pstmt);
            throw std::runtime_error("Failed to bind mr_enclave");
        }
        
        // check if at least 1 result row
        if (sqlite3_step(pstmt) == SQLITE_ROW) {
            whitelisted = true;
        }
        
        sqlite3_finalize(pstmt);
        return whitelisted;
    }

    optional<NetworkConfig> EnclaveNetfilterIndex::get_enclave_ip(sgx_report_body_t *report, in_addr_t _host_ip) {
        (void) _host_ip;

        if (!is_whitelisted_app(report)) return {};

        NetworkConfig nc = {
            .ip = get_free_internal_ip(0),
            .submask = netmask,
            .gateway = gateway,
        };

        return {nc};
    }

    void EnclaveNetfilterIndex::mark_enclave_tunnel_closed(in_addr_t enclave_ip) {
        // call superclass virtual function
        this->EnclaveIndexBase::mark_enclave_tunnel_closed(enclave_ip);
        // try to inform the kernel module
        if (!remove_enclave_from_module(enclave_ip)) {
            std::cerr << "Failed to remove enclave IP " << inet_ntoa({enclave_ip}) << " from kernel module" << std::endl;
        }
    }
 }
