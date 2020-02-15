#include "OpenSSLUVCallbacks.hpp"

#include <iostream>

#include <cassert>



namespace seng {
    void OsslUVCbs::not_touch_read_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
        // don't touch the buffer (note: must set to nullptr && 0, otherwise might have later diff values)
        //assert(buf->base == nullptr && buf->len == 0);
        buf->base = nullptr;
        buf->len = 0;
    }
    
    void OsslUVCbs::free_handle_on_close(uv_handle_t *handle) {
        free(handle);
    }
}
