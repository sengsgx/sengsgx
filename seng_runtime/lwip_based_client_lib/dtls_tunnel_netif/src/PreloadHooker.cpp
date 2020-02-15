#include "PreloadHooker.hpp"

#include <cstring>

#include "HookCommons.hpp"


namespace seng {
    __attribute__((constructor)) void init_real_libc_pointers() {
#ifdef DEBUG_PRINT
        printf("Starting to load pointers to real libc functions\n");
        fflush(stdout);
#endif
        
        void *handle = nullptr;
        handle = dlopen("libc.so.6", RTLD_LAZY);
        if(unlikely(handle == nullptr)) throw std::runtime_error("dlopen() failed");
        
        init_sockets_hooks(handle);
        
        init_sending_hooks(handle);
        init_receiving_hooks(handle);
        
        init_polling_hooks(handle);
        
        init_sockctrl_hooks(handle);
        
        init_getinfo_hooks(handle);
        
#ifdef DEBUG_PRINT
        printf("Hook pointers loaded\n");
        fflush(stdout);
#endif
    }
}
