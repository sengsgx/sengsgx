#include "MbedtlsUVCallbacks.hpp"

#include <iostream>

#include <cassert>

#include <mbedtls/net_sockets.h>


namespace seng {
    void MbedUVCbs::not_touch_read_buffer(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf) {
        // don't touch the buffer (note: must set to nullptr && 0, otherwise might have later diff values)
        //assert(buf->base == nullptr && buf->len == 0);
        buf->base = nullptr;
        buf->len = 0;
    }
    
    /*!
     * BIO read callback for mbedTLS
     * Simply retrieves the raw socket fd from the libuv handle and afterwards
     * performs a standard recv() on it.
     */
    int MbedUVCbs::wrapped_mbedtls_net_recv(void *ctx, unsigned char *buf, size_t len) {
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t *) ctx, &fd);
        // grab socket fd from tcp/udp handle and call regular network read function
        return mbedtls_net_recv(&fd, buf, len);
    }
    
    /*!
     * BIO write callback for mbedTLS
     * Issues a write request with the decrypted data received from mbedTLS.
     */
    int MbedUVCbs::wrapped_mbedtls_net_send(void *ctx, const unsigned char *buf, size_t len) {
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t *) ctx, &fd);
        // grab socket fd from tcp/udp handle and call regular network read function
        return mbedtls_net_send(&fd, buf, len);
    }
    
    int MbedUVCbs::wrapped_mbedtls_net_recv_timeout( void *ctx, unsigned char *buf,
                                                    size_t len, uint32_t timeout ) {
        uv_os_fd_t fd;
        uv_fileno((uv_handle_t *) ctx, &fd);
        // grab socket fd from tcp/udp handle and call regular network read function
        return mbedtls_net_recv_timeout(&fd, buf, len, timeout);
    }
    
    void MbedUVCbs::free_handle_on_close(uv_handle_t *handle) {
        free(handle);
    }
}
