#include "DT_OnLoadSENGStarter_OpenSSL.hpp"

extern "C" {
    #include <lwip/sys.h>
    #include <lwip/tcpip.h>
    #include <lwip/netifapi.h>
    
    #include <lwip/dns.h>
}

//#include <sys/prctl.h>

#include <DT_RaSSLTunnelNetif_OpenSSL.hpp>
#include "HookCommons.hpp"

//#define MEASURE_NETIF_SETUP_TIME
// target_compile_definitions(...)

//#define MEASURE_FINE_GRAINED_SETUP_TIME
// target_compile_definitions(...)


namespace seng {
    bool init_tunnel_netif(void);
    void lwip_thread_init(void *arg);
    
    __attribute__((constructor)) void startup_lwip_and_tunnel_netif() {
#ifdef MEASURE_NETIF_SETUP_TIME
        bool timeofday_ok_total {true};
        struct timeval listen_tv_start_total {}, listen_tv_end_total {};
        if( gettimeofday(&listen_tv_start_total, nullptr) != 0 ) {
            fprintf(stderr, "gettimeofday failed in setup\n");
            fflush(stderr);
            timeofday_ok_total = false;
        }
#endif
        
#ifdef DEBUG_PRINT
        printf("Starting to create lwIP thread and tunnel netif\n");
        fflush(stdout);
#endif
        
        // Not implemented by Graphene(-SGX), also not prctl(PR_SET_NAME)
        //pthread_setname_np(pthread_self(), "SENG|s main/app");
        
        err_t err;
        sys_sem_t init_sem;
        
        err = sys_sem_new(&init_sem, 0);
        LWIP_ASSERT("failed to create init_sem", err == ERR_OK);
        LWIP_UNUSED_ARG(err);
    
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        printf("tcpip_thread_usec;ssl_init_usec;rsa_gen_key_usec;get_quote_usec;"
               "obtain_ias_report_usec;gen_x509_usec;setup_dtls_tunnel_ip_usec;"
               "tunnel_poll_thread_usec");
#ifdef MEASURE_NETIF_SETUP_TIME
        printf(";total_setup_usec\n");
#else
        printf("\n");
#endif
        bool timeofday_ok {true};
        struct timeval listen_tv_start {}, listen_tv_end {};
        if( gettimeofday(&listen_tv_start, nullptr) != 0 ) {
            fprintf(stderr, "gettimeofday failed in setup\n");
            fflush(stderr);
            timeofday_ok = false;
        }
#endif
        // need to run separate IP/TCP thread if we want to use lwIP Socket API
        tcpip_init(lwip_thread_init, &init_sem);    // spawn tcpip (lwip) thread
#ifdef MEASURE_FINE_GRAINED_SETUP_TIME
        if( timeofday_ok ) {
            if ( gettimeofday(&listen_tv_end, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
            } else {
                auto diff_sec = listen_tv_end.tv_sec - listen_tv_start.tv_sec;
                auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end.tv_usec - listen_tv_start.tv_usec;
                printf("%ld;", total_diff_in_ms);
                //fflush(stdout);
            }
        }
#endif
        
        sys_sem_wait(&init_sem);    // wait for init of lwip thread to finish
        sys_sem_free(&init_sem);
        
#ifdef DEBUG_PRINT
        printf("Finished lwIP thread and netif initialization phase\n");
        fflush(stdout);
#endif
        
#ifdef MEASURE_NETIF_SETUP_TIME
        if( timeofday_ok_total ) {
            if ( gettimeofday(&listen_tv_end_total, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in setup\n");
                fflush(stderr);
            } else {
                auto diff_sec = listen_tv_end_total.tv_sec - listen_tv_start_total.tv_sec;
                auto total_diff_in_ms = diff_sec * 1000000 + listen_tv_end_total.tv_usec - listen_tv_start_total.tv_usec;
                printf("%ld\n", total_diff_in_ms);
                fflush(stdout);
            }
        }
#endif
        
#ifdef DEBUG_PRINT
        printf("App will not execute\n");
        fflush(stdout);
#endif
    }
    __attribute__((destructor))  void shutdown_tunnel_netif() {
#ifdef DEBUG_PRINT
        printf("Library Destructor!\n");
        fflush(stdout);
#endif
        
        // closes tunnel and sets link down
        auto tun_netif_ptr = (RaSSLTunnelNetifOpenSSL *) tunnel_netif.state;
        // if initialization was successful!
        if (tun_netif_ptr != nullptr) {
            tun_netif_ptr->locked__graceful_shutdown();
        
            // wait for netif read-loop thread to finish
            pthread_join(tun_netif_ptr->netif_rloop_thread_id, nullptr);
        
            netifapi_netif_set_link_down(&tunnel_netif);
            netifapi_netif_set_down(&tunnel_netif); // new (prob. not required?)
        
            // remove netif
            netifapi_netif_remove(&tunnel_netif);
            
            // new
            tunnel_netif.state = nullptr;
            
            /* BUGGY in Graphene-SGX
            if ( pthread_cancel(tun_netif_ptr->lwip_thread_id) == 0 ) {
                std::cout << "Informed lwIP pthread to cancel" << std::endl;
                pthread_join(tun_netif_ptr->lwip_thread_id, nullptr);
                std::cout << "Finished waiting for lwIP pthread!" << std::endl;
                std::cout.flush();
            } else {
                std::cout << "Informing lwIP pthread failed" << std::endl;
            }
            std::cout.flush();
             */
            
            // Not required anymore for Singleton pattern (would cause crash in free())
            //delete tun_netif_ptr;
        }
    }
    
    bool init_tunnel_netif(void) {
        // ip, netmask and gw set automatically when SSL tunnel has been established
        if (netif_add(&tunnel_netif, NULL, NULL, NULL, NULL, RaSSLTunnelNetifOpenSSL::netif_init_trmpln, tcpip_input) == NULL) {
            tunnel_netif.state = nullptr;
            return false;
        }
        netif_set_default(&tunnel_netif);
        netif_set_up(netif_default);    // starting from now on, lwIP stack will accept input IP packets from netif/link
        return true;
    }
    
    void lwip_thread_init(void *arg) {
        sys_sem_t *init_sem;
        LWIP_ASSERT("arg != NULL", arg != NULL);
        init_sem = (sys_sem_t*)arg;
        
        // Not implemented by Graphene(-SGX), also not prctl(PR_SET_NAME)
        //if (pthread_setname_np(pthread_self(), "SENG|s lwIP") != 0) perror("pthread setname");
        //if (prctl(PR_SET_NAME, (unsigned long) "DEMO DEMO", 0, 0, 0) != 0) perror("prctl");
        
        /* init randomizer again (seed per thread) */
        srand((unsigned int)time(0));
        
        /* init network interface ([ip,netmask,gw] auto-set as soon as tunnel is up) */
        bool success = init_tunnel_netif();
        
        if (success) {
            ip_addr_t dns_server {};
            // TODO: set to internal/GW one instead
            IP_ADDR4(&dns_server, 8, 8, 8, 8);
            dns_setserver(0, &dns_server);
        }
            
        // wakeup main thread
        sys_sem_signal(init_sem);
        
        if (!success) {
            fprintf(stderr, "Failed lwIP + Netif startup!\n");
            fflush(stderr);
            exit(1);
        }
    }
}
