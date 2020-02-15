#include "SSLEngine_OpenSSL.hpp"

extern "C" {
    #include <ra-challenger.h>
}

#include <iostream>

#include <arpa/inet.h>

#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdexcept>

//#define OSSL_DEBUG_PRINTS


namespace seng {
    SSLEngineOpenSSL::SSLEngineOpenSSL(std::string cipher_str) : cipher(cipher_str) {
        SSL_load_error_strings();
        SSL_library_init();
        
        ctx = SSL_CTX_new(DTLSv1_2_server_method());
        if (ctx == nullptr) throw std::runtime_error("SSL_CTX_new failed");
    }
    
    SSLEngineOpenSSL::~SSLEngineOpenSSL() {
        SSL_CTX_free(ctx);
    }
    
    // TODO: not lock-protected; but server is anyway single-threaded at the moment!
    // source: https://web.archive.org/web/20150806185102/http://sctp.fh-muenster.de:80/dtls/dtls_udp_echo.c
#define COOKIE_SECRET_LENGTH 16
    static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
    static int cookie_initialized=0;
    
    // source: https://web.archive.org/web/20150806185102/http://sctp.fh-muenster.de:80/dtls/dtls_udp_echo.c
    static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
    {
#ifdef OSSL_DEBUG_PRINTS
        std::cout << "generate_cookie" << std::endl;
#endif
        
        unsigned char *buffer, result[EVP_MAX_MD_SIZE];
        unsigned int length = 0, resultlength;
        union {
            struct sockaddr_storage ss;
            struct sockaddr_in6 s6;
            struct sockaddr_in s4;
        } peer;
        
        /* Initialize a random secret */
        if (!cookie_initialized)
        {
            if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
            {
                printf("error setting random cookie secret\n");
                return 0;
            }
            cookie_initialized = 1;
        }
        
        /* Read peer information */
        (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
        
        /* Create buffer with peer's address and port */
        length = 0;
        switch (peer.ss.ss_family) {
            case AF_INET:
                length += sizeof(struct in_addr);
                break;
            //case AF_INET6:
            //    length += sizeof(struct in6_addr);
            //    break;
            default:
                throw std::runtime_error("unknown peer address");
                //OPENSSL_assert(0);
                //break;
        }
        length += sizeof(in_port_t);
        buffer = (unsigned char*) OPENSSL_malloc(length);
        
        if (buffer == NULL)
        {
            printf("out of memory\n");
            return 0;
        }
        
        switch (peer.ss.ss_family) {
            case AF_INET:
                memcpy(buffer,
                       &peer.s4.sin_port,
                       sizeof(in_port_t));
                memcpy(buffer + sizeof(peer.s4.sin_port),
                       &peer.s4.sin_addr,
                       sizeof(struct in_addr));
                break;
            //case AF_INET6:
            //    memcpy(buffer,
            //           &peer.s6.sin6_port,
            //           sizeof(in_port_t));
            //    memcpy(buffer + sizeof(in_port_t),
            //           &peer.s6.sin6_addr,
            //           sizeof(struct in6_addr));
            //    break;
            default:
                throw std::runtime_error("unknown peer address");
                //OPENSSL_assert(0);
                //break;
        }
        
        /* Calculate HMAC of buffer using the secret */
        HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
             (const unsigned char*) buffer, length, result, &resultlength);
        OPENSSL_free(buffer);
        
        memcpy(cookie, result, resultlength);
        *cookie_len = resultlength;
        
        return 1;
    }
    
    // source: https://web.archive.org/web/20150806185102/http://sctp.fh-muenster.de:80/dtls/dtls_udp_echo.c
    static int verify_cookie(SSL *ssl, unsigned char *cookie, unsigned int cookie_len)
    {
#ifdef OSSL_DEBUG_PRINTS
        std::cout << "verfiy_cookie" << std::endl;
#endif
        
        unsigned char *buffer, result[EVP_MAX_MD_SIZE];
        unsigned int length = 0, resultlength;
        union {
            struct sockaddr_storage ss;
            struct sockaddr_in6 s6;
            struct sockaddr_in s4;
        } peer;
        
        /* If secret isn't initialized yet, the cookie can't be valid */
        if (!cookie_initialized)
            return 0;
        
        /* Read peer information */
        (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);
        
        // TODO: only support AF_INET
        
        /* Create buffer with peer's address and port */
        length = 0;
        switch (peer.ss.ss_family) {
            case AF_INET:
                length += sizeof(struct in_addr);
                break;
            //case AF_INET6:
            //    length += sizeof(struct in6_addr);
            //    break;
            default:
                throw std::runtime_error("unsupported peer address");
                //OPENSSL_assert(0);
                //break;
        }
        length += sizeof(in_port_t);
        buffer = (unsigned char*) OPENSSL_malloc(length);
        
        if (buffer == NULL)
        {
            printf("out of memory\n");
            return 0;
        }
        
        switch (peer.ss.ss_family) {
            case AF_INET:
                memcpy(buffer,
                       &peer.s4.sin_port,
                       sizeof(in_port_t));
                memcpy(buffer + sizeof(in_port_t),
                       &peer.s4.sin_addr,
                       sizeof(struct in_addr));
                break;
            //case AF_INET6:
            //    memcpy(buffer,
            //           &peer.s6.sin6_port,
            //           sizeof(in_port_t));
            //    memcpy(buffer + sizeof(in_port_t),
            //           &peer.s6.sin6_addr,
            //           sizeof(struct in6_addr));
            //    break;
            default:
                throw std::runtime_error("unknown peer address");
                //OPENSSL_assert(0);
                //break;
        }
        
        /* Calculate HMAC of buffer using the secret */
        HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
             (const unsigned char*) buffer, length, result, &resultlength);
        OPENSSL_free(buffer);
        
        if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
//            std::cout << "SUCCESS" << std::endl;
            return 1;
        }
        
//        std::cout << "fail" << std::endl;
        return 0;
    }
    
    static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
#ifdef OSSL_DEBUG_PRINTS
        std::cout << "Verfiy_callback" << std::endl;
#endif
        
        /* OpenSSL's default verification logic returns error on
           self-signed certificates. */
        X509* crt = X509_STORE_CTX_get_current_cert(ctx);
        if (preverify_ok == 0) {
            int err = X509_STORE_CTX_get_error(ctx);
#ifdef OSSL_DEBUG_PRINTS
            printf("error: %d (if 19, might be root CA!)\n", err);
#endif
            //TODO: assert(err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
            // == 18
            // 19: X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN (root CAs count!)
            // Fail!
            if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) {
                fprintf(stderr, "unexpected error: %d during certificate checking\n", err);
                return 0;
            }
        }
        
        int der_len = i2d_X509(crt, NULL);
        if(der_len <= 0) throw std::runtime_error("der_len <= 0");
        
        unsigned char der[der_len];
        unsigned char *p = der;
        i2d_X509(crt, &p);
        
        int rc = verify_sgx_cert_extensions(der, der_len);
#ifdef OSSL_DEBUG_PRINTS
        printf("Verifying SGX certificate extensions ... %s\n", rc == 0 ? "Success" : "Fail");
#endif
        return !rc;
    }
    
    void SSLEngineOpenSSL::configure(std::string cert_file_path,
                              std::string key_file_path) {
        
        int ret = SSL_CTX_set_cipher_list(ctx, cipher.data());
        if (ret != 1) throw std::runtime_error("set_cipher_list failed");
        
        // otherwise ECDHE does not work!
        SSL_CTX_set_ecdh_auto(ctx, 1);
        
        ret = SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &verify_callback);
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, &verify_callback);
        
        // cookies MUST be enabled here and below!
        SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
        SSL_CTX_set_cookie_verify_cb(ctx, verify_cookie);
        
        SSL_CTX_set_read_ahead(ctx, 1);
        
        ret = SSL_CTX_use_certificate_file(ctx, cert_file_path.c_str(), SSL_FILETYPE_PEM);
        if (ret != 1) throw std::runtime_error("loading certificate failed");
        
        ret = SSL_CTX_use_RSAPrivateKey_file(ctx, key_file_path.c_str(), SSL_FILETYPE_PEM);
        if (ret != 1) throw std::runtime_error("loading RSA key failed");
        
        ret = SSL_CTX_check_private_key(ctx);
        if (ret != 1) throw std::runtime_error("certificate and private key inconsistent");
    }
}
