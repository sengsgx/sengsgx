#ifndef SENG_PRELOAD_HOOKER_HPP
#define SENG_PRELOAD_HOOKER_HPP

#include <unistd.h>     // already defines socklen_t; note that sys/socket.h collides with lwip/socket.h

#include "hooks/getinfo.hpp"
#include "hooks/polling.hpp"
#include "hooks/receiving.hpp"
#include "hooks/sending.hpp"
#include "hooks/sockctrl.hpp"
#include "hooks/sockets.hpp"

namespace seng {
    static __attribute__((constructor (101))) void init_real_libc_pointers();
}

#endif /* SENG_PRELOAD_HOOKER_HPP */
