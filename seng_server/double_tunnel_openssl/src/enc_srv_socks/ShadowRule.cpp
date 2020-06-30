#include "enc_srv_socks/ShadowRule.hpp"

#include <cstdlib>

#include <arpa/inet.h>

#include <unistd.h>
#include <cassert>

#include <iostream>

//#define DEBUG_SHADOWRULE


namespace seng {
    ShadowRule::ShadowRule(in_port_t port, uint8_t protocol,
                           in_addr_t enclave_ip, in_addr_t client_ip) :
    port(port), protocol(protocol), enclave_ip(enclave_ip), client_ip(client_ip),
    state(RuleState::DISABLED) {}
    
    ShadowRule::ShadowRule(const ShadowRule &other) :
    ShadowRule(other.port, other.protocol, other.enclave_ip, other.client_ip) {
        state = other.get_state();
    }
    
    RuleState ShadowRule::get_state() const {
        return state;
    }
    
    void ShadowRule::add_rule_spec(std::stringstream &stream) {
        stream << iptables_cli_ip_prefix <<  inet_ntoa({client_ip}) << " ";    // bcs. inet_ntoa static buffer
        stream << iptables_tcp
        << iptables_srv_port_prefix << ntohs(port) << " "               // bcs. network-byte order
        << iptables_dnat
        << iptables_enc_ip_prefix << inet_ntoa({enclave_ip}) << " ";    // bcs. inet_ntoa static buffer
        stream << iptables_mute_output;
    }
    
    bool ShadowRule::add_to_system() {
        if (state == RuleState::ENABLED) throw std::runtime_error("Rule already enabled");
        std::stringstream output_cmd_string, prerouting_cmd_string {};
        
        // cmd for OUTPUT rule
        output_cmd_string << iptables_bin_table << iptables_add_to_output_chain;
        add_rule_spec(output_cmd_string);
        
        // cmd for PREROUTING rule
        prerouting_cmd_string << iptables_bin_table << iptables_add_to_prerouting_chain;
        prerouting_cmd_string << iptables_preroute_in_interface;
        add_rule_spec(prerouting_cmd_string);
        
        // (optionally:) ask user/admin for permission
        if (!ask_for_cmd_permission(output_cmd_string.str()) ||
            !ask_for_cmd_permission(prerouting_cmd_string.str())) return false;
        
        // try to add rules
        auto res1 = execute_root_cmd(output_cmd_string.str());
        auto res2 = execute_root_cmd(prerouting_cmd_string.str());
        
        // if failure
        if (res1 != 0 || res2 != 0) {
            delete_from_system();
            return false;
        }
        
        // success
        state = RuleState::ENABLED;
        return true;
    }
    
    bool ShadowRule::delete_from_system() {
        if (state == RuleState::DISABLED) throw std::runtime_error("Rule already disabled");
        std::stringstream output_cmd_string, prerouting_cmd_string {};
        
        // cmd for OUTPUT rule
        output_cmd_string << iptables_bin_table << iptables_delete_from_output_chain;
        add_rule_spec(output_cmd_string);
        
        // cmd for PREROUTING rule
        prerouting_cmd_string << iptables_bin_table << iptables_delete_from_prerouting_chain;
        prerouting_cmd_string << iptables_preroute_in_interface;
        add_rule_spec(prerouting_cmd_string);
        
        // (optionally:) ask user/admin for permission
        if (!ask_for_cmd_permission(output_cmd_string.str()) ||
            !ask_for_cmd_permission(prerouting_cmd_string.str())) return false;
        
        // try to add rules
        auto res1 = execute_root_cmd(output_cmd_string.str());
        auto res2 = execute_root_cmd(prerouting_cmd_string.str());
        
        // TODO: what to do on failure?!
        if (res1 != 0 || res2 != 0) {
            std::cerr << "[CAUTION] Failed to remove ShadowRule" << std::endl;
            return false;
        }
        
        // success
        state = RuleState::DISABLED;
        return true;
    }
    
    bool ShadowRule::ask_for_cmd_permission(const std::string &cmd) {
#ifdef DEBUG_SHADOWRULE
        std::cout << "Do you want to issue the following command [AS ROOT] ?" << std::endl
        << "'" << cmd << "'" << std::endl
        << "y/n?" << std::endl;
        char c;
        std::cin >> c;
        if (c != 'y' && c != 'Y') {
            std::cout << "User Input wasn't y/Y, so don't execute it" << std::endl;
            return false;
        }
#endif
        return true;
    }

    int ShadowRule::execute_root_cmd(const std::string &cmd) {
        int cmd_res;
        
        // <TMP_ROOT>
        uid_t old_euid { geteuid() };
        gid_t old_egid { getegid() };
        assert(old_euid != 0 && old_egid != 0);
        try {
            assert(geteuid() == old_euid && getegid() == old_egid);
            if( seteuid(0) < 0 ) { throw std::runtime_error("Failed to become Root again"); }
            if( setegid(0) < 0 ) { int ret; do {ret = seteuid(old_euid); perror(nullptr);} while(ret < 0); }
            
            assert(geteuid() == 0 && getegid() == 0);
#ifdef DEBUG_SHADOWRULE
            std::cout << "TMP ROOT MODE: enabled" << std::endl;
#endif
            
            // <ACTUAL CODE>
            cmd_res = std::system(cmd.data());
            // </ACTUAL CODE>
            
            int ret;
            do {ret = setegid(old_egid); if(ret<0) perror(nullptr);} while(ret < 0);
            do {ret = seteuid(old_euid); if(ret<0) perror(nullptr);} while(ret < 0);
            assert(geteuid() == old_euid && getegid() == old_egid);
#ifdef DEBUG_SHADOWRULE
            std::cout << "TMP ROOT MODE: disabled" << std::endl;
#endif
        } catch (...) {
            int ret;
            if (getegid() == 0) do {ret = setegid(old_egid); if(ret<0) perror(nullptr);} while(ret < 0);
            if (geteuid() == 0) do {ret = seteuid(old_euid); if(ret<0) perror(nullptr);} while(ret < 0);
            assert(geteuid() == old_euid && getegid() == old_egid);
#ifdef DEBUG_SHADOWRULE
            std::cout << "TMP ROOT MODE: disabled" << std::endl;
#endif
        }
        // </TMP_ROOT>
        
        return cmd_res;
    }
}
