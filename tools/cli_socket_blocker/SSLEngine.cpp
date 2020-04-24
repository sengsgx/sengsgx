#include "SSLEngine.hpp"

#include <stdexcept>

#include <mbedtls/platform.h>
#include <mbedtls/debug.h>


namespace seng {
    static void my_debug( void *ctx, int level,
                         const char *file, int line,
                         const char *str )
    {
        ((void) level);
        
        mbedtls_fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
        fflush(  (FILE *) ctx  );
    }
    
    SSLEngine::SSLEngine(SSLType type) : type(type) {
        mbedtls_ssl_config_init(&conf);
        mbedtls_ssl_cache_init(&cache);
        mbedtls_x509_crt_init(&srvcert);
        mbedtls_pk_init(&pkey);
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_ssl_cookie_init(&cookie_ctx);
    }
    
    SSLEngine::~SSLEngine() {
        mbedtls_ssl_config_free(&conf);
        mbedtls_ssl_cache_free(&cache);
        mbedtls_x509_crt_free(&srvcert);
        mbedtls_pk_free(&pkey);
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ssl_cookie_free(&cookie_ctx);
    }
    
    void SSLEngine::configure(const unsigned char *server_cert_buf, size_t srv_crt_len,
                              const unsigned char *ca_certs_buf, size_t cas_len,
                              const unsigned char *priv_srv_key, size_t keylen,
                              const unsigned char *key_pwd, size_t pwdlen,
                              int(*cli_crt_verify_fct)(void *, mbedtls_x509_crt *, int, uint32_t *),
                              bool is_server) {
        
        // Load Server certificate and CA chain
        if (mbedtls_x509_crt_parse(&srvcert, server_cert_buf, srv_crt_len) != 0)
            throw std::runtime_error("mbedtls_x509_crt_parse failed on srv_crt");
        
        if(mbedtls_x509_crt_parse(&srvcert, ca_certs_buf, cas_len) != 0)
            throw std::runtime_error("mbedtls_x509_crt_parse failed on cas_pem");
        
        // Load Server private key
        if(mbedtls_pk_parse_key(&pkey, priv_srv_key, keylen, key_pwd, pwdlen) != 0)
            throw std::runtime_error("mbedtls_pk_parse_key failed");
        
        // DRBG = Deterministic Random Byte Generator
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func,
                                  &entropy, nullptr, 0) != 0)
            throw std::runtime_error("mbedtls_ctr_drbg_seed failed");
        
        // TLS / DTLS specific configuration
        int transport_type;
        switch (type) {
            case SSLType::TLS:
                transport_type = MBEDTLS_SSL_TRANSPORT_STREAM;
                break;
            case SSLType::DTLS:
                transport_type = MBEDTLS_SSL_TRANSPORT_DATAGRAM;
                break;
            default:
                throw std::runtime_error("Unsupported SSL Type");
        }
        int ssl_role;
        if (is_server) ssl_role = MBEDTLS_SSL_IS_SERVER;
        else ssl_role = MBEDTLS_SSL_IS_CLIENT;
        if (mbedtls_ssl_config_defaults(&conf, ssl_role, transport_type,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0)
            throw std::runtime_error("mbedtls_ssl_config_defaults failed");
        
        
        // random number generator fybctuib
        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (conf.f_rng == nullptr)
            throw std::runtime_error("tls_engine.conf.f_rng == nullptr");
        
        mbedtls_debug_set_threshold(0);
        mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
        
        // session cache functions
        mbedtls_ssl_conf_session_cache(&conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
        
        mbedtls_ssl_conf_ca_chain( &conf, srvcert.next, NULL );
        
        // Set Server certificate and private key
        if (mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey) != 0)
            throw std::runtime_error("mbedtls_ssl_conf_own_cert failed");
       
        if (type == SSLType::DTLS) {
            if(mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg) != 0 )
                throw std::runtime_error("mbedtls_ssl_cookie_setup failed");
            
            //mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write,
            //                              mbedtls_ssl_cookie_check, &cookie_ctx);
            mbedtls_ssl_conf_dtls_cookies(&conf, nullptr, nullptr, &cookie_ctx);
        }
        
        
        // add optional client certificate verification
        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

        // sgx-ra-tls certificate verification mechanism
        if( cli_crt_verify_fct != nullptr) {
            mbedtls_ssl_conf_verify(&conf, cli_crt_verify_fct, nullptr);
        }
    }
}
