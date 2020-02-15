#ifndef SENG_OPENSSL_UV_CALLBACKS_HPP
#define SENG_OPENSSL_UV_CALLBACKS_HPP

#include <uv.h>


namespace seng {
    struct OsslUVCbs {
        OsslUVCbs() = default;
        ~OsslUVCbs() = default;
        
        //! UV allocation callback
        static void not_touch_read_buffer(uv_handle_t *, size_t, uv_buf_t *);
        
        //! UV close callback
        static void free_handle_on_close(uv_handle_t *);
    };
}

#endif /* SENG_OPENSSL_UV_CALLBACKS_HPP */
