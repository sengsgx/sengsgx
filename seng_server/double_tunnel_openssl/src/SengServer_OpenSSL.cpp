#include "SengServer_OpenSSL.hpp"

#include "TunnelToEnclave_OpenSSL.hpp"
#include "OpenSSLUVCallbacks.hpp"

// SGX-RA-TLS headers
extern "C" {
#include <ra.h>
#include <ra-challenger.h>
}

#include "EnclaveIndex_adapted.hpp"
#include "EnclaveSqlite3Index.hpp"
#include "EnclaveNetfilterIndex.hpp"

#include <iostream>
#include <stdexcept>

#include <cassert>

#include <unistd.h>

#include <netinet/in.h>

#include <experimental/optional>

using namespace std::experimental;
//#include <optional>

//#define DEBUG_SENG_SRV


namespace seng {
    SengServerOpenSSL::SengServerOpenSSL(std::string &ip_addr, in_port_t tunnel_port,
                             volatile sig_atomic_t * stop_marker_ptr,
                             SengSrvConfig config) :
    stop_marker_ptr(stop_marker_ptr), check_period_in_ms(5000), is_shutting_down(false),
    shadow_srv_enabled(config.enable_shadow_srv), tunnel_ip(ip_addr), tunnel_port(tunnel_port),
    ssl_engine("ECDHE-RSA-AES256-GCM-SHA384"), shadower_service_up(nullptr) {
        
        // use dummy, or Sqlite3-based enclave index
        auto opt_db_path = config.opt_db_path;
        if (!opt_db_path) {
            enclave_idx_sp = std::make_shared<EnclaveIndex>();
        } else {
            if (config.use_seng_netfilter_module) {
                enclave_idx_sp = std::make_shared<EnclaveNetfilterIndex>(opt_db_path->c_str());
            } else {
                enclave_idx_sp = std::make_shared<EnclaveSqliteIndex>(opt_db_path->c_str());
            }
        }
        
        ip_pckt_fwder_sp = std::make_shared<PacketForwarder>(enclave_idx_sp);
        // DTLS configuration (TODO: make paths configurable via CLI args)
        ssl_engine.configure("./srv_cert.pem", "./srv_key.pem");
        // event loop
        init_event_loop();
        //

        welcome_socket.udp_srv_fd = (uv_udp_t *) malloc(sizeof(uv_udp_t));
        assert(welcome_socket.udp_srv_fd != nullptr);
        
        ip_pckt_fwder_sp->add_to_event_loop(&loop);
    }
    
    SengServerOpenSSL::~SengServerOpenSSL() {
        free(welcome_socket.udp_srv_fd);
        free_event_loop();
        
        if (shadower_service_up) {
            shadower_service_up->send_stop_signal();
            shadow_service_thread.join();
        }
        
        // Free BIO/SSL objects if required
        if (ssl != nullptr) {
            SSL_free(ssl); // seems to call BIO_free_all() internally
            ssl = nullptr;
            udp_bio = nullptr;
        }
    }
    
    void SengServerOpenSSL::init_event_loop() {
        if (uv_loop_init(&loop) != 0)
            throw std::runtime_error("Failed UV Loop allocation");
        
        if (uv_timer_init(&loop, &watcher_fd) != 0) {
            uv_loop_close(&loop);
            throw std::runtime_error("Failed to init UV Watchdog Handler");
        }
        
        watcher_fd.data = this;
        if (uv_timer_start(&watcher_fd, timer_trmpln, 0, check_period_in_ms) != 0) {
            uv_close((uv_handle_t *)&watcher_fd, nullptr);
            int res;
            do {  res = uv_loop_close(&loop); if(res<0) std::cout << "Failed loop close" << std::endl; }
            while(res != 0);
            throw std::runtime_error("Failed to start UV Watchdog Handler");
        }
    }
    void SengServerOpenSSL::free_event_loop() {
        if (uv_loop_close(&loop) == UV_EBUSY)
            throw std::logic_error("Tried to close UV Loop in destructor w/o "
                                   "stopping it correctly");
    }
    
    void SengServerOpenSSL::timer_trmpln(uv_timer_t *h) {
        if (h == nullptr) return;
        assert(h->data != nullptr);
        ((SengServerOpenSSL *)h->data)->check_shutdown_signal();
    }
    
    void SengServerOpenSSL::check_shutdown_signal() {
        assert(stop_marker_ptr != nullptr);
        if (*stop_marker_ptr != 0) {
            std::cout << "SengServer has received stop signal" << std::endl;
            if (shadower_service_up) {
                stop_shadow_server();
            } else {
                std::cout << "ShadowServer has already been shut down" << std::endl;
            }
            
            // TODO: should also start shutdown process of SengServer
            std::cout << "Stopping loop" << std::endl;
            uv_stop(&loop);
            std::cout << "Walking all handles and mark them closed" << std::endl;
            uv_walk(&loop, shutdown_trmpln, (void *)this);
            
            // TODO: THIS IS NOT ALLOWED "uv_run() is not reentrant; must not be called from callback"
            //auto res = uv_run(&loop, UV_RUN_DEFAULT); // to make close CB be executed
            //assert(res == 0); // fails
            
            is_shutting_down = true;
            std::cout << "SengServer shutdown process has been initialised." << std::endl;
            *stop_marker_ptr = 0;
        }
    }
    
    void SengServerOpenSSL::shutdown_trmpln(uv_handle_t *h, void *arg) {
        if (h == nullptr) return;
        assert(arg != nullptr);
        ((SengServerOpenSSL *)arg)->shutdown_walker(h);
    }
    
    void SengServerOpenSSL::shutdown_walker(uv_handle_t *h) {
        assert(h != nullptr);
        // Server handles (srv socket, timer)
        if (h->data == this) {
            // closing
            uv_close(h, nullptr);
            return;
        }

        // Buggy handles w/o userdata (should NOT occur)
        if (h->data == nullptr) {
            std::cerr << "[CAUTION] Unexpected UV handle without userdata" << std::endl;
            uv_close(h, nullptr);
            return;
        }
        
        // Client handles (tunnel connections)
        // TODO: TTE (D)TLS Sockets, which require extra cleanup routines,
        // that we do not yet have; so close none-gracefully at the moment
        uv_close(h, nullptr);
    }
    
    void SengServerOpenSSL::run() {
        if (is_shutting_down) throw std::logic_error("SengServer has already been shut down; you should destruct it now");
        setup_welcome_socket();
        if (shadow_srv_enabled) {
            setup_clisock_shadower_srv();
            start_shadow_srv_thread();
        }
        start_event_loop();
    }
    
    void SengServerOpenSSL::setup_welcome_socket() {
        setup_udp_srv_socket();
    }
    
    void SengServerOpenSSL::setup_udp_srv_socket() {
        // create UDP socket
        int ret = uv_udp_init(&loop, welcome_socket.udp_srv_fd);
        welcome_socket.udp_srv_fd->data = (void *) this;
        
        struct sockaddr_in srv_sock_addr;
        ret |= uv_ip4_addr(tunnel_ip.data(), tunnel_port, &srv_sock_addr);
        ret |= uv_udp_bind(welcome_socket.udp_srv_fd, (sockaddr *) &srv_sock_addr, UV_UDP_REUSEADDR);
        
        // start waiting for new UDP communication
        ret |= uv_udp_recv_start(welcome_socket.udp_srv_fd,
                                 OsslUVCbs::not_touch_read_buffer,
                                 SengServerOpenSSL::trmpln_incoming_udp_communication);
        
        if(ret != 0)
            throw std::runtime_error("UDP Server socket setup failed");
        
        // check that it is indeed in non-blocking mode
        check_in_nonblocking_mode((uv_handle_t *)welcome_socket.udp_srv_fd);
        
        // Create OpenSSL BIO and SSL session objects
        int srv_sock_fd;
        uv_fileno((uv_handle_t *)welcome_socket.udp_srv_fd, &srv_sock_fd);
        udp_bio = BIO_new_dgram(srv_sock_fd, BIO_NOCLOSE);
        
        ssl = SSL_new(ssl_engine.ctx);
        SSL_set_bio(ssl, udp_bio, udp_bio);
        SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
        SSL_set_mtu(ssl, ip_pckt_fwder_sp->tunnel_mtu);
        
        // "Enable cookie exchange" (Server-only?)
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
    }
    
    void SengServerOpenSSL::start_event_loop() {
        std::cout << "Starting event loop" << std::endl;
        int res = uv_run(&loop, UV_RUN_DEFAULT);
        
        // seems there was an error on startup
        if (res != 0 && !is_shutting_down) throw std::runtime_error("Failed to start the event loop");
        
        // shutdown request seems to have temporarily closed the loop;
        // shuold now rerun it to finish up the close callbacks;
        // TODO: Currently skipped; might be bcs. we only use nullptr as dummy close CBs at the moment
        if (res != 0 && is_shutting_down) {
            // TODO: it must be ensured that no new handles are created, and all
            //      have been marked as closed; otherwise this will again run
            //      for an unlimited time;
            std::cout << "Rerun loop to finish up close callbacks" << std::endl;
            res = uv_run(&loop, UV_RUN_DEFAULT);
            if (res != 0) {
                std::cerr << "Something went wrong with uv_run() during shutdown process" << std::endl;
                return;
            }
        }
            
        // res == 0; Note that this should not happen if !is_shutting_down
        assert(is_shutting_down);
        std::cout << "Loop has stopped execution as all handles have been closed." << std::endl;
    }
    
    void SengServerOpenSSL::trmpln_incoming_udp_communication(uv_udp_t* handle, ssize_t nread,
                                                const uv_buf_t* buf,
                                                const struct sockaddr* addr,
                                                unsigned flags) {
#ifdef DEBUG_SENG_SRV
        std::cout << "Trampoling: Incoming UDP communication" << std::endl;
#endif
        
        // as we use ignoring alloc CB
        assert(nread == UV_ENOBUFS && addr == nullptr && flags == 0);
        assert(handle->data != nullptr);
        ((SengServerOpenSSL *)handle->data)->incoming_udp_communication();
    }
    void SengServerOpenSSL::incoming_udp_communication() {
#ifdef DEBUG_SENG_SRV
        std::cout << "New incoming UDP communication" << std::endl;
        std::cout.flush();
#endif
        int srv_sock_fd;
        uv_fileno((uv_handle_t *)welcome_socket.udp_srv_fd, &srv_sock_fd);
        
        /* Check if we need to bind a new BIO and SSL to server UDP socket */
        if (udp_bio == nullptr) {
            assert(ssl == nullptr);
            udp_bio = BIO_new_dgram(srv_sock_fd, BIO_NOCLOSE);
            ssl = SSL_new(ssl_engine.ctx);
            SSL_set_bio(ssl, udp_bio, udp_bio);
            SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
            SSL_set_mtu(ssl, ip_pckt_fwder_sp->tunnel_mtu);
            
            // "Enable cookie exchange"
            SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);
            
        }
        
        /* Listen */
        struct sockaddr_in cli_addr {};
        int ret = DTLSv1_listen(ssl, &cli_addr);
        if (ret <= 0) return;
        
        // currently only support IPv4
        if (cli_addr.sin_family != AF_INET) {
            std::cerr << "DTLSv1_listen() returned a non-IPv4 address!" << std::endl;
            std::cerr.flush();
            
            SSL_free(ssl); // ok, bcs. BIO_NOCLOSE
            ssl = nullptr;
            udp_bio = nullptr;
            return;
        }
        
#ifdef DEBUG_SENG_SRV
        std::cout << "Client IP: " << inet_ntoa(cli_addr.sin_addr) << std::endl;
        std::cout.flush();
#endif
       /* TODO: have to switch to single DTLS socket in future for bullet proof multi-enclave support;
        *       it has to accept all packets and forward them to the respective TunnelToEnclave object(s);
        *       multiple welcome sockets could be used for load balancing;
        *       current approach relies on SO_REUSEPORT and Linux kernel's behaviour of delivering
        *       UDP packets to the same UDP socket that accepted the "connection", even if other sockets share IP/Port.
        *       It works with multi-enclaves, but only if each new enclave is always connected to the
        *       current (fresh/unshared) welcome socket, which sometimes seems to fail!
        */


        /* Create new Socket for the new Client (steals BIO and SSL of Server) */
        // for libuv
        auto cli_uv_udp = (uv_udp_t *) malloc(sizeof(uv_udp_t));
        if (cli_uv_udp == nullptr) {
            // Close Server Socket SSL Context
            SSL_shutdown(ssl);
            SSL_free(ssl); // ok, bcs. BIO_NOCLOSE
            ssl = nullptr;
            udp_bio = nullptr;
            return;
        }
        uv_udp_init(&loop, cli_uv_udp);
        
        // actual socket
        int client_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (client_fd < 0) {
            // Close new UDP socket
            uv_close((uv_handle_t *) cli_uv_udp, OsslUVCbs::free_handle_on_close);
            
            // Close Server Socket SSL Context
            SSL_shutdown(ssl);
            SSL_free(ssl); // ok, bcs. BIO_NOCLOSE
            ssl = nullptr;
            udp_bio = nullptr;
            return;
        }
        
        int one = 1;
        setsockopt(client_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
#ifdef SO_REUSEPORT
        setsockopt(client_fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif
        
        // non-blocking
        //int flags;
        //flags = fcntl(client_fd, F_GETFL, 0);
        //fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in srv_sock_addr;
        uv_ip4_addr(tunnel_ip.data(), tunnel_port, &srv_sock_addr);
        
        // bind to server address
        if (bind(client_fd, (struct sockaddr *)&srv_sock_addr, sizeof(srv_sock_addr)) < 0) {
            // Close new UDP socket
            uv_close((uv_handle_t *) cli_uv_udp, OsslUVCbs::free_handle_on_close);
            close(client_fd);
            
            // Close Server Socket SSL Context
            SSL_shutdown(ssl);
            SSL_free(ssl); // ok, bcs. BIO_NOCLOSE
            ssl = nullptr;
            udp_bio = nullptr;
            return;
        }
        
        // connect to new client
        if(connect(client_fd, (struct sockaddr *)&cli_addr, sizeof(struct sockaddr_in)) < 0) {
            // Close new UDP socket
            uv_close((uv_handle_t *) cli_uv_udp, OsslUVCbs::free_handle_on_close);
            close(client_fd);
            
            // Close Server Socket SSL Context
            SSL_shutdown(ssl);
            SSL_free(ssl); // ok, bcs. BIO_NOCLOSE
            ssl = nullptr;
            udp_bio = nullptr;
            return;
        }
        
        // connect to libuv
        uv_udp_open(cli_uv_udp, client_fd);
        
        // set blocking for the moment
        int flags;
        flags = fcntl(client_fd, F_GETFL, 0);
        fcntl(client_fd, F_SETFL, flags & ~O_NONBLOCK);

        // Steal BIO and SSL of Server
        BIO_set_fd(udp_bio, client_fd, BIO_CLOSE);
        BIO_ctrl(udp_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &cli_addr);
        
        // Set and activate timeouts
        struct timeval timeout_short {
            .tv_sec = 3,
            .tv_usec = 0
        };
        BIO_ctrl(udp_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_short);
        
#ifdef DEBUG_SENG_SRV
        std::cout << "Going to create new TunnelToEnclave object" << std::endl;
#endif
        
        /* Mark Server BIO and SSL as stolen */
        BIO *cli_bio = udp_bio;
        SSL *cli_ssl = ssl;
        udp_bio = nullptr;
        ssl = nullptr;
        
        // perform some cleanup, then create new one (TODO: different way of cleanup triggering)
        enclave_idx_sp->cleanup_closed_tunnels();
        
        // TODO: could throw exception, which would leak memory!
        auto tte_up = std::make_unique<TunnelToEnclaveOpenSSL>(cli_ssl, ip_pckt_fwder_sp,
                                                        enclave_idx_sp, cli_uv_udp);
        cli_uv_udp->data = (void *) tte_up.get();
        
        in_addr_t new_ip;
        try {
            tte_up->establish_ssl_session();
#ifdef DEBUG_SENG_SRV
            std::cout << "Going to assign internal IP to new Enclave" << std::endl;
#endif
            
            optional<NetworkConfig> opt_nc;
            opt_nc = enclave_idx_sp->get_enclave_ip(&tte_up->quote.report_body, tte_up->untrusted_tunnel_host_ip);
            
            if(!opt_nc) {
                throw std::runtime_error("Failed to get IP for given enclave-hostIP pair");
            }
            new_ip = opt_nc->ip;
            //new_ip = enclave_idx_sp->get_free_internal_ip();
                                                    
            tte_up->assign_internal_ip(new_ip, opt_nc->submask, opt_nc->gateway);
            
            // set non-blocking now!
            flags = fcntl(client_fd, F_GETFL, 0);
            fcntl(client_fd, F_SETFL, flags | O_NONBLOCK);
            
            // Set and activate longer timeouts now
            struct timeval timeout_long {
                .tv_sec = 120,
                .tv_usec = 0
            };
            BIO_ctrl(cli_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_long);
            
        } catch(std::exception &e) {
            std::cerr << "Failed to establish Tunnel to new Enclave; " << e.what() << std::endl;
            return;
        }

        // success, so add to list
        auto tte_ptr = tte_up.get();
        enclave_idx_sp->add_new_enclave_tunnel(std::move(tte_up), new_ip);
#ifdef DEBUG_SENG_SRV
        std::cout << "Going to start Enclave event listeners" << std::endl;
#endif
        tte_ptr->start_event_listeners();
        
        // check that it is indeed in non-blocking mode
        check_in_nonblocking_mode((uv_handle_t *)welcome_socket.udp_srv_fd);
        check_in_nonblocking_mode((uv_handle_t *)cli_uv_udp);
        
        /*
         * NOTE:
         * in UDP case, we don't know till the DTLS handshake phase whether a
         * UDP packet really kicks of a new DTLS session.
         * So to avoid resource exhaustion-based DoS, it would be better to not
         * create state (e.g. TunnelToEnclave object) till the DTLS handshake
         * has been successfully performed.
         * Note however, that we already make use of DTLS cookies.
         *
         * For the moment, we leave that open as future extension.
         */
    }
    
    void SengServerOpenSSL::check_in_nonblocking_mode(uv_handle_t *h) {
        // check that it is indeed in non-blocking mode
        int tmp_fd {-1};
        int ret = uv_fileno(h, &tmp_fd);
        assert (ret == 0);
        assert (tmp_fd >= 0);
        assert ( (fcntl(tmp_fd, F_GETFL, 0) & O_NONBLOCK) != 0 );
    }
    
    void SengServerOpenSSL::setup_clisock_shadower_srv() {
        shadower_service_up = std::make_unique<CliSockShadower>(enclave_idx_sp);
    }
    
    void SengServerOpenSSL::start_shadow_srv_thread() {
        shadow_service_thread = std::thread{&CliSockShadower::run_cmd_server, shadower_service_up.get()};
    }
    
    void SengServerOpenSSL::stop_shadow_server() {
        std::cout << "Signalling STOP to ShadowServer" << std::endl;
        shadower_service_up->send_stop_signal();
        try {
            shadow_service_thread.join();
            
            // clean-up
            shadower_service_up.reset(nullptr);
            std::cout << "Finished clean-up of ShadowServer" << std::endl;
            
        } catch(std::system_error &se) {
            std::cerr << "joining for ShadowService failed: " << se.std::exception::what() << std::endl;
            // TODO: retry depending on error?
            throw;
        }
    }
}
