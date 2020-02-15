#include "EnclaveIndex_adapted.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>

#include <stdexcept>
#include <algorithm>

#include <cassert>

//#define DEBUG_ENCIDX

/* TODO: choose IPs based on SGX report; Currently we always pick from private Subnetwork */

namespace seng {
    EnclaveIndex::EnclaveIndex() :
    base_subnet(192 | 168 << 8 | 178 << 16),        // 192.168.178.0/24; Note: BigEndian (net-order)
    netmask(255 | 255 << 8 | 255 << 16 | 0 << 24),  // 255.255.255.0 (/24)
    gateway(base_subnet | 1 << 24),                 // 192.168.178.1
    active_enclaves(), ip_to_enclave_idx(), disconnected_enclaves(),
    next_potential_client_number(2), cli_ip_to_rules(), client_num_bitset()
    {
        // block 0, GW IP and broadcast
        client_num_bitset.set(0);
        client_num_bitset.set(1);
        client_num_bitset.set(255);
    }
    EnclaveIndex::~EnclaveIndex() {}
   
    /* Add SGX Report as Function Argument and pick IP from respective subnetwork */
    in_addr_t EnclaveIndex::get_free_internal_ip() {
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
            for (auto i=next_potential_client_number+1; i!=next_potential_client_number; i=(i+1)%255) {
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
    
    TunnelToEnclaveOpenSSL *
    EnclaveIndex::get_enclave_handle_by_ip(in_addr_t internal_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        if (ip_to_enclave_idx.count(internal_ip) == 0) return nullptr;
        return ip_to_enclave_idx.at(internal_ip);
    }
    
    void EnclaveIndex::mark_enclave_tunnel_closed(in_addr_t internal_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        // erase index
        ip_to_enclave_idx.erase(internal_ip);
        
        // get TTE unique pointer
        auto it = std::find_if(active_enclaves.begin(), active_enclaves.end(),
                               [internal_ip](std::unique_ptr<TunnelToEnclaveOpenSSL> &up)->bool {
                                   return up->internal_enclave_ip == internal_ip;
                               });
        
        // case: found nothing
        if (it == active_enclaves.end()) {
            std::cerr << "There is no active Enclave with internal IP: " << inet_ntoa({internal_ip}) << std::endl;
            return;
        }
        
        // take ownership of it
        disconnected_enclaves.push_back(std::move(*it));
        // remove empty up
        active_enclaves.erase(it);
    }
    
    void EnclaveIndex::cleanup_closed_tunnels() {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        
        // Go through TTE and release their Cli Numbers (/ internal IP Addresses)
        for (const auto &tte_up : disconnected_enclaves) {
            auto free_ip = tte_up->internal_enclave_ip;
            auto cli_num = free_ip >> 24;
            
            // Valid client number?
            if (2 <= cli_num && cli_num <= 255) {
                client_num_bitset.reset(cli_num);
                std::cout << "IP: " << inet_ntoa({free_ip}) << " became unused" << std::endl;
                
            // ERROR: invalid client number
            } else {
                /* TODO:
                 *  If we want this to throw, we will need to remove each
                 *  Enclave directly after checking to avoid IP resue before
                 *  destruction.
                 */
                std::cerr << "FATAL: one of the Enclaves to-be-freed had an out-of-range IP" << std::endl;
                //throw std::runtime_error("FATAL: one of the Enclaves to-be-freed had an out-of-range IP");
            }
        }
        
        // Destruct all TTE objects now
        disconnected_enclaves.clear();
    }
    
    bool EnclaveIndex::is_active_enclave(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        return ip_to_enclave_idx.count(internal_enclave_ip) > 0;
    }
    
    optional<in_addr_t> EnclaveIndex::get_ip_of_enclaves_tunnel_host(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        if (ip_to_enclave_idx.count(internal_enclave_ip) == 0) return {};
        auto tte_ptr = ip_to_enclave_idx.at(internal_enclave_ip); // throw would be bug
        return { tte_ptr->untrusted_tunnel_host_ip };
    }
    
    sgx_quote_t EnclaveIndex::get_enclave_quote(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        auto tte_ptr = ip_to_enclave_idx.at(internal_enclave_ip);
        return { tte_ptr->quote };
    }
    
    bool EnclaveIndex::is_already_shadowed(in_port_t port, uint8_t proto, in_addr_t client_ip) {
        assert(proto == IPPROTO_TCP || proto == IPPROTO_UDP);
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        
        // any rules?
        if(cli_ip_to_rules.count(client_ip) == 0) return false;
        
        const auto &rules = cli_ip_to_rules.at(client_ip);
        const auto &it = std::find_if(rules.begin(), rules.end(),
                               [port, proto, client_ip](const ShadowRule &r)->bool {
                                   assert(r.client_ip == client_ip);
                                   assert(r.protocol == IPPROTO_TCP || r.protocol == IPPROTO_UDP);
                                   return r.port == port && r.protocol == proto;
                               });
        
        // found no matching rule for this client IP
        if (it == rules.end()) return false;
        
#ifdef DEBUG_ENCIDX
        std::cout << "Shadowing " << (proto == IPPROTO_TCP ? "tcp" : "udp") << "/" << ntohs(port)
        << " has already been requested for shadowing by Enclave IP "
        << inet_ntoa({it->enclave_ip}) << std::endl;
#endif
        
        // rule already exists
        return true;
    }
    
    bool EnclaveIndex::commit_shadow_rule(ShadowRule rule) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        
        // add new entry with empty rule list
        if(cli_ip_to_rules.count(rule.client_ip) == 0) {
            std::vector<ShadowRule> empty_list {};
            cli_ip_to_rules[rule.client_ip] = empty_list;
        }
        
        // get shadow rule list
        auto &rules = cli_ip_to_rules.at(rule.client_ip);   // throw would be a bug
        
        // check rule does not already exist (redundant)
        if( std::find(rules.begin(), rules.end(), rule) != rules.end() ) return false;
        
        // try to add rule to system
        if (rule.get_state() == RuleState::DISABLED && !rule.add_to_system()) {
            std::cerr << "Failed to enable rule" << std::endl;
            return false;
        }
        
        // push rule to list
        rules.push_back(rule);
        return true;
    }
    
    optional<ShadowRule> EnclaveIndex::get_shadow_rule(int handle, in_addr_t enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        throw std::logic_error("Not implemented, yet");
    }
 }
