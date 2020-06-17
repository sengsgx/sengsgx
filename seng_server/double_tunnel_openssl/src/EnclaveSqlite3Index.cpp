#include "EnclaveSqlite3Index.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>

#include <stdexcept>
#include <algorithm>
#include <cstring>

#include <cassert>

//#define DEBUG_ENCIDX


const char *SIMPLE_QUERY_STR = "SELECT apps.mr_enclave, apps.mr_signer, apps.host_subnet, apps.host_submask, enclave_subnets.subnet, enclave_subnets.submask, enclave_subnets.gateway FROM apps JOIN enclave_subnets ON apps.enc_subnet_id=enclave_subnets.id WHERE apps.mr_enclave == ?;";


namespace seng {
    static unsigned int get_number_of_set_bytes_ip4(in_addr_t netorder_submask);

    SubnetMetadata::SubnetMetadata(in_addr_t base_subnet, in_addr_t base_submask, in_addr_t base_gateway) :
        subnet(base_subnet & base_submask), submask(base_submask),
        subnet_size(static_cast<int>((ntohl(~base_submask)) + 1) - 2),
        gateway(base_gateway), next_tested_ip_index(0),
        client_num_bitset(subnet_size) {

#ifdef DEBUG_ENCIDX
        std::cout << "subnets_size: " << subnet_size << std::endl;
#endif

        // Check that gateway is in the subnet
        if ((gateway & submask) != subnet) throw std::runtime_error("Gateway not in subnet");
    }

    static unsigned int get_number_of_set_bytes_ip4(in_addr_t netorder_submask) {
        unsigned int set_bits {0};
        unsigned int t {ntohl(~netorder_submask)};
        while (t > 0) {
            set_bits++;
            t >>= 1;
        }
        return 32 - set_bits;
    }

    void EnclaveSqliteIndex::init_database(const char *path_to_db) {
        if (sqlite3_open(path_to_db, &db_con) != SQLITE_OK) {
            throw std::runtime_error("Failed to open db");
            std::cerr << "Failed to open db" << std::endl;
        }
    }

    void EnclaveSqliteIndex::cache_defined_subnets() {
        sqlite3_stmt *pstmt {nullptr};
        const char *GET_SUBNETS = "SELECT subnet, submask, gateway FROM enclave_subnets;";
        
        /* CREATE PREPARED STATEMENT */
        int ret = sqlite3_prepare_v2(db_con, GET_SUBNETS, strlen(GET_SUBNETS), &pstmt, nullptr);
        if (ret != SQLITE_OK) {
            throw std::runtime_error("Failed to query defined enclave subnetworks");
        }
        
        /* EVALUATE STATEMENT */
        while((ret = sqlite3_step(pstmt)) == SQLITE_ROW) {
            unsigned int res_subnet, res_submask, res_gateway;
            res_subnet = sqlite3_column_int64(pstmt, 0);
            res_submask = sqlite3_column_int64(pstmt, 1);
            res_gateway = sqlite3_column_int64(pstmt, 2);
            
            // 0: reserved, max: broadcast
            int res_num_hosts = static_cast<int>((~(ntohl(res_submask))) + 1) - 2;
            
            if (res_num_hosts < 0) {
                std::cerr << "Error: subnet with <0 clients: " << res_num_hosts << std::endl;
                continue;
            }
            
            int res_gw_number = ntohl(~res_submask & res_gateway);
            if (res_gw_number < 0 && res_gw_number >= res_num_hosts) {
                std::cerr << "Error: gateway number not in range: " << res_gw_number << std::endl;
                continue;
            }
            
//#ifdef DEBUG_ENCIDX
            char subnet_str[INET_ADDRSTRLEN]; // 16
            inet_ntop(AF_INET, &res_subnet, subnet_str, INET_ADDRSTRLEN);
                   
            char submask_str[INET_ADDRSTRLEN]; // 16
            inet_ntop(AF_INET, &res_submask, submask_str, INET_ADDRSTRLEN);
                   
            char gw_str[INET_ADDRSTRLEN]; // 16
            inet_ntop(AF_INET, &res_gateway, gw_str, INET_ADDRSTRLEN);
            
            std::cout << "Enclave Subnet: " << subnet_str << "/" << get_number_of_set_bytes_ip4(res_submask) << ", Netmask: " << submask_str << " (" << res_num_hosts << " ips), Gateway: " << gw_str << std::endl;
//#endif
            
                       
            // add cache entry with information about enclave subnet
            encsub_to_info.emplace(
                std::piecewise_construct,
                std::forward_as_tuple(res_subnet & res_submask),
                std::forward_as_tuple(res_subnet, res_submask, res_gateway)
            );
            
            std::cout << "Placed new EnclaveIP object into map" << std::endl;

            // mark gateway IP as used
            encsub_to_info.at(res_subnet & res_submask).client_num_bitset[res_gw_number-1] = true;
        }
        
        // cleanup
        sqlite3_finalize(pstmt);
        
        // no more rows
        if (ret != SQLITE_DONE) {
            throw std::runtime_error("Error during querying of defined enclave subnetworks");
        }
    }

    EnclaveSqliteIndex::EnclaveSqliteIndex(const char *path_to_db) :
    EnclaveIndexBase(), encsub_to_info()
    {
        // TODO: check that database exists (otherwise creates empty one)
        
        /* connect to the database */
        init_database(path_to_db);
        
        /* query and cache defined enclave subnetworks */
        cache_defined_subnets();
    }

    EnclaveSqliteIndex::~EnclaveSqliteIndex() {
        // TODO
        sqlite3_close(db_con);
    }
    
    in_addr_t EnclaveSqliteIndex::get_free_internal_ip(in_addr_t enc_subnet) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        
        struct SubnetMetadata &info = encsub_to_info.at(enc_subnet);
        
        in_addr_t ip {0};
        
        // Check if client number is non-assigned
        if (!info.client_num_bitset.at(info.next_tested_ip_index)) {
            // unassigned, so can fallthrough
            // fallthrough
            
        // Are all in use?
        } else if (std::all_of(info.client_num_bitset.begin(), info.client_num_bitset.end(), [](bool v) { return v; })) {
            throw std::runtime_error("Currently out of interal IP addresses");
            
        // Iterate until we find next free one (there has to be at least 1)
        } else {
            auto success {false};
            for (auto i=(info.next_tested_ip_index+1)%info.subnet_size; i!=info.next_tested_ip_index; i=(i+1)%info.subnet_size) {
                if (!info.client_num_bitset.at(i)) {
                    // found unused one
                    info.next_tested_ip_index = i;
                    success = true;
                    break;
                }
            }
            if (!success) throw std::runtime_error("Did not find an unused IP although there should be at least one");
        }

#ifdef DEBUG_ENCIDX  
        // IP is 1 bigger than index
        std::cout << "subnet: " << info.subnet << ", number of set bytes: " << get_number_of_set_bytes_ip4(info.submask) << std::endl;
        std::cout << "info.submask: " << info.submask << std::endl;
#endif

        ip = htonl(ntohl(info.subnet) | (info.next_tested_ip_index+1));
        
        char ip_str[INET_ADDRSTRLEN]; // 16
        inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
        std::cout << "New IP: " << ip_str << std::endl;

        // increment index
        info.next_tested_ip_index = (info.next_tested_ip_index+1) % info.subnet_size;
        
        return ip;
    }
    
    void EnclaveSqliteIndex::add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);

        /* To which Enclave Subnet does the IP belong? */
          for (std::pair<const unsigned int, struct SubnetMetadata>& element : encsub_to_info) {
            if ( (element.first) ==
                (enclave_ip & element.second.submask) ) {
                
                // client number
                unsigned int cli_idx = ntohl(~element.second.submask & enclave_ip) - 1;
                //unsigned int cli_idx = (enclave_ip >> element.second.submask) - 1;
                
                // Cli number marked as in use?
                if (element.second.client_num_bitset.at(cli_idx)) {
                    throw std::runtime_error("The IP request for the new Enclave is already marked as in use");
                }
                
                // mark as in use
                element.second.client_num_bitset[cli_idx] = true;
                // add reference
                ip_to_enclave_idx[enclave_ip] = tte_up.get();
                // move to list
                active_enclaves.push_back(std::move(tte_up));
                return;
            }
        }
        
        throw std::runtime_error("Enclave IP does not belong to any defined subnet");
    }
    
    bool EnclaveSqliteIndex::release_enclave_ip(in_addr_t enclave_ip) {
        
        /* To which Enclave Subnet does the IP belong? */
        for (std::pair<const unsigned int, struct SubnetMetadata>& element : encsub_to_info) {
            if ( (element.first) ==
                (enclave_ip & element.second.submask) ) {
                
                // client number
                unsigned int cli_idx = ntohl(~element.second.submask & enclave_ip) - 1;
                //unsigned int cli_idx = (enclave_ip >> element.second.submask) - 1;
                
                // valid?
                if (cli_idx >= element.second.subnet_size) {
                    return false;
                }
                
                // release / mark as unused
                element.second.client_num_bitset[cli_idx] = false;
                
                return true;
            }
        }
        return false;
    }

    bool EnclaveSqliteIndex::is_whitelisted_app(sgx_report_body_t *report) {
        
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

    optional<NetworkConfig> EnclaveSqliteIndex::get_enclave_ip(sgx_report_body_t *report, in_addr_t host_ip) {
        
        if (!is_whitelisted_app(report)) return {};
        
        optional<in_addr_t> enclave_subnet {};
        sqlite3_stmt *pstmt {nullptr};
         const char *GET_SUBNET = "SELECT apps.host_subnet, apps.host_submask, enclave_subnets.subnet, enclave_subnets.submask FROM apps JOIN enclave_subnets ON apps.enc_subnet_id=enclave_subnets.id WHERE mr_enclave == ?;";
       
         /* CREATE PREPARED STATEMENT */
         int ret = sqlite3_prepare_v2(db_con, GET_SUBNET, strlen(GET_SUBNET), &pstmt, nullptr);
         if (ret != SQLITE_OK) {
             throw std::runtime_error("Failed to query shielded app enclave subnetworks");
         }
     
        /* BIND VALUES TO PREPARED STATEMENT */
        // TODO: correct memory cleanup?
        ret = sqlite3_bind_blob(pstmt, 1, report->mr_enclave.m, SGX_HASH_SIZE, SQLITE_STATIC);
        if (ret != SQLITE_OK) {
            sqlite3_finalize(pstmt);
            throw std::runtime_error("Failed to bind mr_enclave");
        }
        
        /* EVALUATE STATEMENT */
        while((ret = sqlite3_step(pstmt)) == SQLITE_ROW) {
            unsigned int res_host_net, res_host_mask, res_subnet, res_submask;
            res_host_net = sqlite3_column_int64(pstmt, 0);
            res_host_mask = sqlite3_column_int64(pstmt, 1);
            res_subnet = sqlite3_column_int64(pstmt, 2);
            res_submask = sqlite3_column_int64(pstmt, 3);
            
            // is host IP in the subnet?
            if ( (res_host_net & res_host_mask) ==
                 (host_ip & res_host_mask) ) {
                enclave_subnet = {res_subnet & res_submask};
                break;
            }
        }
        
        // cleanup
        sqlite3_finalize(pstmt);
        
        // error?
        if (ret != SQLITE_ROW && ret != SQLITE_DONE) {
            std::cerr << "Error during querying of enclave subnetwork for new enclave: " << ret << std::endl;
            enclave_subnet = {};
        }
        
        if (!enclave_subnet) return {};

        NetworkConfig nc {
            .ip = get_free_internal_ip(*enclave_subnet),
            .submask = get_submask(*enclave_subnet),
            .gateway = get_gateway(*enclave_subnet),
        };

        return {nc};
    }

    in_addr_t EnclaveSqliteIndex::get_gateway(in_addr_t enc_subnet) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        struct SubnetMetadata &info = encsub_to_info.at(enc_subnet);
        return info.gateway;
    }

    in_addr_t EnclaveSqliteIndex::get_submask(in_addr_t enc_subnet) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        struct SubnetMetadata &info = encsub_to_info.at(enc_subnet);
        return info.submask;
    }
 }
