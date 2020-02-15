#ifndef SENG_SSLENGINE_HPP
#define SENG_SSLENGINE_HPP

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/ssl_cookie.h>


namespace seng {
    enum class SSLType {
        TLS,
        DTLS
    };
    
    struct SSLEngine {
        mbedtls_ssl_config conf;
        mbedtls_ssl_cache_context cache;
        mbedtls_x509_crt srvcert;
        mbedtls_pk_context pkey;
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        
        // DTLS-specific
        mbedtls_ssl_cookie_ctx cookie_ctx;
        
        SSLType type;
        
        SSLEngine(SSLType);
        ~SSLEngine();

        void configure(const unsigned char *, size_t,
                       const unsigned char *, size_t,
                       const unsigned char *, size_t, const unsigned char *, size_t,
                       int(*)(void *, mbedtls_x509_crt *, int, uint32_t *),
                       bool);
    };
}

#endif /* SENG_SSLENGINE_HPP */
