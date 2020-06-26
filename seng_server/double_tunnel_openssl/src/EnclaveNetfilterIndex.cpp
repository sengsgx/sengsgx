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
    void EnclaveNetfilterIndex::init_netfilter_connection() {
        if (prep_nl_sock() != SQLITE_OK) {
            throw std::runtime_error("Failed to open netlink socket to SENG module (Is the kernel module loaded?)");
        }
    }

    void EnclaveNetfilterIndex::cleanup_netfilter_connection() {
        flush_module();
        cleanup_nl_sock();
    }

    std::vector<std::string>
    EnclaveNetfilterIndex::query_categories(uint8_t mr_enclave[]) {
        sqlite3_stmt *pstmt {nullptr};
        std::vector<std::string> categories {};
        const char *QUERY_APP_CATEGORIES = "SELECT categories.name FROM categories JOIN apps ON categories.apps_id == apps.id WHERE apps.mr_enclave == ?;";
        /* CREATE PREPARED STATEMENT */
        int ret = sqlite3_prepare_v2(db_con, QUERY_APP_CATEGORIES, strlen(QUERY_APP_CATEGORIES), &pstmt, nullptr);
        if (ret != SQLITE_OK) {
            std::cerr << "error: " << sqlite3_errmsg(db_con) << std::endl;
            throw std::runtime_error("Failed to query app catgories");
        }
        
        /* BIND VALUES TO PREPARED STATEMENT */
        // TODO: correct memory cleanup?
        ret = sqlite3_bind_blob(pstmt, 1, mr_enclave, SGX_HASH_SIZE, SQLITE_STATIC);
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

    bool EnclaveNetfilterIndex::add_enclave_to_module(uint32_t enclave_ip, uint8_t mr_enclave[],
            uint32_t host_ip) {

        // Add Enclave IP to netfilter module
        bool success = 0 == add_enclave_ack(enclave_ip, mr_enclave, host_ip, NULL);

        // Check if there is already an other active enclave running the same application
        // NOTE: *enclave_idx_guard already held*
        auto it = std::find_if(active_enclaves.begin(), active_enclaves.end(),
            [mr_enclave,enclave_ip](std::unique_ptr<TunnelToEnclaveOpenSSL> &up)->bool {
                return (up->internal_enclave_ip != enclave_ip)
                    && (0 == memcmp(up->quote.report_body.mr_enclave.m, mr_enclave, SGX_HASH_SIZE));
            });
        
        // case: found something
        if (it != active_enclaves.end()) return success;

        // Query and add categories
        auto categories = query_categories(mr_enclave);
#ifdef DEBUG_ENCIDX
        std::cout << "Will now try to add categories!" << std::endl;
#endif
        for (std::string &s : categories) {
#ifdef DEBUG_ENCIDX
            std::cout << "Adding category: " << s << std::endl;
#endif
            cat_to_app_ack(mr_enclave, s.c_str());
        }
        return success;
    }

    bool EnclaveNetfilterIndex::remove_enclave_from_module(uint32_t enclave_ip) {
        return 0 == remove_enclave_ack(enclave_ip);
    }

    void EnclaveNetfilterIndex::init_database(const char *path_to_db) {
        if (sqlite3_open(path_to_db, &db_con) != SQLITE_OK) {
            throw std::runtime_error("Failed to open db");
            std::cerr << "Failed to open db" << std::endl;
        }
    }

    EnclaveNetfilterIndex::EnclaveNetfilterIndex(const char *path_to_db) :
    EnclaveIndex()
    {
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
    
    void EnclaveNetfilterIndex::add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t enclave_ip) {
        // TODO: problem is that tte will become invalid after moving it into the superclass
        in_addr_t host_ip = tte_up->untrusted_tunnel_host_ip;
        uint8_t mr_enclave[SGX_HASH_SIZE];
        std::memcpy(mr_enclave, tte_up->quote.report_body.mr_enclave.m, SGX_HASH_SIZE);

        // moves tte
        this->EnclaveIndex::add_new_enclave_tunnel(std::move(tte_up), enclave_ip);

        // add to module (todo: problem that not under idx lock?)
        if (!this->add_enclave_to_module(enclave_ip, mr_enclave, host_ip)) {
            throw std::runtime_error("Failed to add new Enclave to Netfilter module");
        }
    }

    void EnclaveNetfilterIndex::mark_enclave_tunnel_closed(in_addr_t enclave_ip) {
        // call superclass virtual function
        this->EnclaveIndexBase::mark_enclave_tunnel_closed(enclave_ip);
        // try to inform the kernel module (todo: problem that it's outside lock?)
        if (!remove_enclave_from_module(enclave_ip)) {
            std::cerr << "Failed to remove enclave IP " << inet_ntoa({enclave_ip}) << " from kernel module" << std::endl;
        }
    }
 }
