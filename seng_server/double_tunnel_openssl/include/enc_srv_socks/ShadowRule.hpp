#ifndef SENG_SHADOWRULE_HPP
#define SENG_SHADOWRULE_HPP

#include <netinet/in.h>

#include <sstream>


namespace seng {
    enum class RuleState {
        DISABLED = 0,
        ENABLED,
    };
    
    class ShadowRule {
    public:
        ShadowRule(in_port_t port, uint8_t protocol,
                   in_addr_t enclave_ip, in_addr_t client_ip);
        
        // Copy constructor (works if we make port, and co. const again)
        ShadowRule(const ShadowRule &other);
        
        /*
         * TODO: had them const, but Vector only allows assignable elements ...
         *  might use unique_ptr in rule list, but that introduces additional overhead
         */
        in_port_t port;
        uint8_t protocol;
        in_addr_t enclave_ip;
        in_addr_t client_ip;
        
        // Enclave IP does not have to match, bcs. Client can run multiple Enclaves
        bool operator==(const ShadowRule& right) const {
            return (port == right.port) &&
            (protocol == right.protocol) &&
            (client_ip == right.client_ip);
        }
        
        bool add_to_system();
        bool delete_from_system();
        RuleState get_state() const;
        
    private:
        RuleState state;
    
        static constexpr const char * add_cmd_template {"iptables -t nat -A SENG_output -d %u.%u.%u.%u -p tcp --destination-port %u -j DNAT --to-destination %u.%u.%u.%u >/dev/null 2>&1"};
        
        static constexpr const char * iptables_bin_table {"iptables -t nat "};
        static constexpr const char * iptables_add_to_output_chain {"-A SENG_output "};
        static constexpr const char * iptables_delete_from_output_chain {"-D SENG_output "};
        static constexpr const char * iptables_cli_ip_prefix {"-d "};
        static constexpr const char * iptables_tcp {"-p tcp "};
        static constexpr const char * iptables_srv_port_prefix {"--destination-port "};
        static constexpr const char * iptables_dnat {"-j DNAT "};
        static constexpr const char * iptables_enc_ip_prefix {"--to-destination "};
        static constexpr const char * iptables_mute_output {">/dev/null 2>&1 "};
        
        static constexpr const char * iptables_add_to_prerouting_chain {"-A SENG_prerouting "};
        static constexpr const char * iptables_delete_from_prerouting_chain {"-D SENG_prerouting "};
        static constexpr const char * iptables_preroute_in_interface {"-i eth0 "};
        
        void add_rule_spec(std::stringstream &stream);
        bool ask_for_cmd_permission(const std::string &cmd);
        
        /*
         * Obviously, this is not cool and a nice attacker gadget, but the official
         * netfilter documentation claims system/popen as the recommended way to
         * interact with iptables.
         */
        int execute_root_cmd(const std::string &cmd);
    };
}

#endif /* SENG_SHADOWRULE_HPP */
