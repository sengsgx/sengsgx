#ifndef SENG_ONLOAD_SENGSTARTER_HPP
#define SENG_ONLOAD_SENGSTARTER_HPP

extern "C" {
    #include <lwip/netif.h>
}

namespace seng {
    static __attribute__((constructor (102))) void startup_lwip_and_tunnel_netif();
    static __attribute__((destructor))  void shutdown_tunnel_netif();
    
    static struct netif tunnel_netif;
}

#endif /* SENG_ONLOAD_SENGSTARTER_HPP */
