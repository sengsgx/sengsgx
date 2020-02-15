#ifndef SENG_ONLOAD_APPBENCH_HPP
#define SENG_ONLOAD_APPBENCH_HPP

#include <sys/time.h>

namespace seng {
    static __attribute__((constructor (105))) void start_measurement();
    static __attribute__((destructor))  void stop_measurement();
    
    static bool timeofday_ok {true};
    static struct timeval tv_start, tv_end;
}

#endif /* SENG_ONLOAD_APPBENCH_HPP */
