#include "SengMain_adapted.hpp"

#include "SengServer_OpenSSL.hpp"

#include <iostream>
#include <string>
#include <thread>
#include <stdexcept>

#include <cstdlib>
#include <cerrno>

#include <unistd.h> // getopt()

#include <netinet/in.h> // struct in_addr, in_port_t


const char *USAGE {"Usage: seng_ossl_tunnel_server [-d <sqlite.db>] <tunnel_port>\n"};

int main(int argc, char *argv[]) {
    bool use_tls = false;
    int c;
    char *db_path {nullptr};
    while ((c = getopt (argc, argv, "hd:")) != -1)
        switch (c)
    {
        case 'h':
            std::cout << USAGE << std::endl;
            return EXIT_SUCCESS;
        case 'd':
            db_path = optarg;
            continue;
        default:
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
    }
    
    // check that one argument exists
    if (optind != argc-1) {
        std::cerr << "ERROR: Wrong number of arguments" << std::endl;
        std::cout << USAGE << std::endl;
        return EXIT_FAILURE;
    }

    // parse given tunnel port number
    unsigned long tunnel_port_ul;
    {
        char *end_ptr;
        errno = 0;
        tunnel_port_ul = std::strtoul(argv[optind], &end_ptr, 10);
        if (errno != 0) {
            std::cerr << "ERROR: given port number overflowed" << std::endl;
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
        } else if (end_ptr == argv[optind]) {
            std::cerr << "ERROR: could not parse port number" << std::endl;
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
        } else if (tunnel_port_ul > 65535) {
            std::cerr << "ERROR: port number exceeds 65535 or is negative"
            << std::endl;
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
        }
    }
    
    auto tunnel_port = (in_port_t) tunnel_port_ul;
    std::string tunnel_ip {"127.0.0.1"}; // NOTE: 0.0.0.0 caused probs. with DTLS
    
    // register signal handler for SIGINT
    if( sigaction(SIGINT, &sigint_handler, nullptr) < 0 ) {
        perror(nullptr);
        std::cerr << "Failed to install SIGINT handler" << std::endl;
        return EXIT_FAILURE;
    }
    
    /*
     * If started as root, temporary reduce privileges until we really need them (iptables).
     * Later it might be cool to split the iptables-controlling code into a separate child process,
     * s.t. we can perma-drop the root privileges from the NGW server process.
     */
    // TODO: reduce it to the respective network capability rather than root requirement
    if (getuid() != 0) {
        std::cout << "The Server must be started as root to support Enclave Server Sockets" << std::endl;
        return EXIT_FAILURE;
    } else {
        // TODO: use getpwnam(), getpwnam_r or request uid/gid via CLI
        if ((setegid(1000) < 0) || (seteuid(1000) < 0)) {
            std::cout << "Failed to temporarily drop Root UID and/or GID" << std::endl;
            perror(nullptr);
            return EXIT_FAILURE;
        }
        // TODO: supplementary groups?
        std::cout << "Temporarily dropped to UID: " << 1000 << " and GID: " << 1000 << std::endl;
    }
    
    // START
    std::cout << "Welcome to the SENG Server" << std::endl;
    
    std::cout << "Tunnel Port: " << tunnel_port << std::endl;
    seng::SengServerOpenSSL seng_server {tunnel_ip, tunnel_port, &stop_marker, (db_path ? make_optional<std::string>(db_path) : nullopt) };
    
    std::thread seng_srv_thread {&seng::SengServerOpenSSL::run, &seng_server};
    try {
        seng_srv_thread.join();
    } catch(std::system_error &se) {
        std::cerr << "Error during thread.join(): " << se.std::exception::what() << std::endl;
        // TODO: Does SIGINT cause this exception? If yes, should restart .join()
    }
    
    // END
    std::cout << "Stopping SENG Server now" << std::endl;
    return EXIT_SUCCESS;
}
