#include "EnclaveIndex_adapted.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>

#include <stdexcept>
#include <algorithm>

#include <cassert>

//#define DEBUG_ENCIDX


namespace seng {
    EnclaveIndex::EnclaveIndex() :
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
    }
    EnclaveIndex::~EnclaveIndex() {
        // TODO
    }
    
    in_addr_t EnclaveIndex::get_free_internal_ip(in_addr_t _enc_subnet) {
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
    
    void EnclaveIndex::add_new_enclave_tunnel(std::unique_ptr<TunnelToEnclaveOpenSSL> tte_up, in_addr_t internal_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);

        // Cli number marked as in use?
        if (client_num_bitset.test(internal_ip >> 24)) {
            throw std::runtime_error("The IP request for the new Enclave is already marked as in use");
        }
        
        // mark as in use
        client_num_bitset.set(internal_ip >> 24);
        // add reference
        ip_to_enclave_idx[internal_ip] = tte_up.get();
        // move to list
        active_enclaves.push_back(std::move(tte_up));
    }
    
    bool EnclaveIndex::release_enclave_ip(in_addr_t enclave_ip) {
     
        auto cli_num = enclave_ip >> 24;
        
        // Valid client number?
        if (2 <= cli_num && cli_num <= 255) {
            client_num_bitset.reset(cli_num);
            return true;
        }
        return false;
    }

    bool EnclaveIndex::is_whitelisted_app(sgx_report_body_t *report) {
        return true;
    }

    optional<NetworkConfig> EnclaveIndex::get_enclave_ip(sgx_report_body_t *_report, in_addr_t _host_ip) {
        (void) _report;
        (void) _host_ip;
        
        NetworkConfig nc = {
            .ip = get_free_internal_ip(0),
            .submask = netmask,
            .gateway = gateway,
        };

        return {nc};
    }
}
