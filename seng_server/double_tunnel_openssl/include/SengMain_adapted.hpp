#ifndef SENG_SENGMAIN_HPP
#define SENG_SENGMAIN_HPP

#include <iostream>
#include <csignal>

volatile sig_atomic_t stop_marker {0};

static void stop_marker_sighandler(int signum) {
    if (signum != SIGINT) {
        std::cerr << "Signal handler for Server Shutdown called with unexpected signal number: " << signum << std::endl;
        return;
    }
    stop_marker++;
}

struct sigaction sigint_handler {
    .__sigaction_handler = { stop_marker_sighandler },
};

#endif /* SENG_SENGMAIN_HPP */
