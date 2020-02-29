#include "EncIdxBase.hpp"
#include "TunnelToEnclave_OpenSSL.hpp"

#include <iostream>

#include <stdexcept>
#include <algorithm>

#include <cassert>

#include <arpa/inet.h>

//#define DEBUG_ENCIDX


namespace seng {
    EnclaveIndexBase::EnclaveIndexBase() :    ip_to_enclave_idx(), active_enclaves(), disconnected_enclaves(), cli_ip_to_rules() {
    
    }
    
    EnclaveIndexBase::~EnclaveIndexBase() {
        // TODO
    }

    TunnelToEnclaveOpenSSL *
EnclaveIndexBase::get_enclave_handle_by_ip(in_addr_t internal_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        if (ip_to_enclave_idx.count(internal_ip) == 0) return nullptr;
        return ip_to_enclave_idx.at(internal_ip);
    }
    
void EnclaveIndexBase::mark_enclave_tunnel_closed(in_addr_t internal_ip) {
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
    
void EnclaveIndexBase::cleanup_closed_tunnels() {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        
        // Go through TTE and release their Cli Numbers (/ internal IP Addresses)
        for (const auto &tte_up : disconnected_enclaves) {
            auto free_ip = tte_up->internal_enclave_ip;
            if (release_enclave_ip(free_ip)) {
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
    
bool EnclaveIndexBase::is_active_enclave(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        return ip_to_enclave_idx.count(internal_enclave_ip) > 0;
    }
    
optional<in_addr_t> EnclaveIndexBase::get_ip_of_enclaves_tunnel_host(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        if (ip_to_enclave_idx.count(internal_enclave_ip) == 0) return {};
        auto tte_ptr = ip_to_enclave_idx.at(internal_enclave_ip); // throw would be bug
        return { tte_ptr->untrusted_tunnel_host_ip };
    }
    
sgx_quote_t EnclaveIndexBase::get_enclave_quote(in_addr_t internal_enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        auto tte_ptr = ip_to_enclave_idx.at(internal_enclave_ip);
        return { tte_ptr->quote };
    }
    
bool EnclaveIndexBase::is_already_shadowed(in_port_t port, uint8_t proto, in_addr_t client_ip) {
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
    
    bool EnclaveIndexBase::commit_shadow_rule(ShadowRule rule) {
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
    
    optional<ShadowRule> EnclaveIndexBase::get_shadow_rule(int handle, in_addr_t enclave_ip) {
        std::unique_lock<std::mutex> lock(enclave_idx_guard);
        throw std::logic_error("Not implemented, yet");
    }
 }
