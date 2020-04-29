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


const char *USAGE {"Usage: seng_ossl_tunnel_server [-d <sqlite.db>] [-s] <tunnel_ipv4> <tunnel_port>\n"
    "\nArguments:\n"
    "tunnel_ipv4     = IPv4 address on which the server will listen\n"
    "tunnel_port     = UDP port on which the server will listen\n"
    "\nOptions:\n"
    "-d <sqlite.db>  = optional path to SQLite3 database\n"
    "-h              = show this help message\n"
    "-s              = enable ShadowServer for auto-nat/port shadowing at 192.168.28.1:2409/tcp\n"};

int main(int argc, char *argv[]) {
    bool use_tls = false;
    int c;
    char *db_path {nullptr};
    bool enable_shadow_srv {false};
    while ((c = getopt (argc, argv, "hd:s")) != -1)
        switch (c)
    {
        case 'h':
            std::cout << USAGE << std::endl;
            return EXIT_SUCCESS;
        case 'd':
            db_path = optarg;
            continue;
        case 's':
            enable_shadow_srv = true;
            continue;
        default:
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
    }

    // '-d' and '-s' together currently not supported yet
    if (db_path && enable_shadow_srv) {
        std::cerr << "ERROR: '-d' and '-s' are not yet supported together. Choose at most one of them." << std::endl;
        std::cout << USAGE << std::endl;
        return EXIT_FAILURE;
    }
    
    // check that two arguments exists
    if (optind != argc-2) {
        std::cerr << "ERROR: Wrong number of arguments" << std::endl;
        std::cout << USAGE << std::endl;
        return EXIT_FAILURE;
    }

    // grab tunnel IP
    if (strcmp("0.0.0.0", argv[optind]) == 0) {
        std::cerr << "ERROR: an explicit IPv4 address has to be specified. \"0.0.0.0\" is invalid" << std::endl;
        std::cout << USAGE << std::endl;
        return EXIT_FAILURE;
    }
    // Warning: SENG Runtime and SDK currently assume 127.0.0.1
    std::string tunnel_ip {argv[optind]}; // NOTE: 0.0.0.0 caused probs. with DTLS

    // parse given tunnel port number
    unsigned long tunnel_port_ul;
    {
        char *end_ptr;
        errno = 0;
        tunnel_port_ul = std::strtoul(argv[optind+1], &end_ptr, 10);
        if (errno != 0) {
            std::cerr << "ERROR: given port number overflowed" << std::endl;
            std::cout << USAGE << std::endl;
            return EXIT_FAILURE;
        } else if (end_ptr == argv[optind+1]) {
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
    seng::SengServerOpenSSL seng_server {tunnel_ip, tunnel_port, &stop_marker, (db_path ? make_optional<std::string>(db_path) : nullopt),
                                        enable_shadow_srv };
    
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
