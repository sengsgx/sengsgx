#include "bench_app_thread/OnLoadAppBench.hpp"

#include <stdio.h>


namespace seng {
    __attribute__((constructor)) void start_measurement() {
        if( gettimeofday(&tv_start, nullptr) != 0 ) {
            fprintf(stderr, "gettimeofday failed in listen\n");
            fflush(stderr);
            timeofday_ok = false;
        }
    }
    
    __attribute__((destructor))  void stop_measurement() {
        if( timeofday_ok ) {
            if ( gettimeofday(&tv_end, nullptr) != 0 ) {
                fprintf(stderr, "gettimeofday failed in listen\n");
                fflush(stderr);
            } else {
                auto diff_sec = tv_end.tv_sec - tv_start.tv_sec;
                auto total_diff_in_ms = diff_sec * 1000000 + tv_end.tv_usec - tv_start.tv_usec;
                printf("\napp_time_in_usec;%ld\n", total_diff_in_ms);
                fflush(stdout);
            }
        }
    }
}
