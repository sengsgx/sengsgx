#include "DT_SSLEngineClient_OpenSSL.hpp"

extern "C" {
    #include "th-lock.h"
}

#include <stdexcept>
#include <cassert>
#include <iostream>

#include <sgx_quote.h>

extern "C" {
    #include <ra-attester.h>
    #include <openssl/obj_mac.h>
}

//#define USE_ECDSA 1
//#define OSSL_SSL_DEBUG_PRINTS


/*
struct CRYPTO_dynlock_value *demo_create (const char *file, int line) {
    std::cout << "dynlock create" << std::endl;
    std::cout.flush();
}
void demo_lock(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line) {
    std::cout << "dynlock lock" << std::endl;
    std::cout.flush();
}

void demo_destroy(struct CRYPTO_dynlock_value *l, const char *file, int line) {
    std::cout << "dynlock destroy" << std::endl;
    std::cout.flush();
}
*/

namespace seng {
    SSLEngineClientOpenSSL::SSLEngineClientOpenSSL(std::string cipher_str,
                                                   std::string server_cert_file) :
    cipher(cipher_str), ca_file(server_cert_file) {
#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "OpenSSL Engine Constructor" << std::endl;
        std::cout.flush();
#endif

// We move this outside SSLEngine in case of measurement, bcs. otherwise we miss the static OpenSSL library initialization
#ifndef MEASURE_FINE_GRAINED_SETUP_TIME
        SSL_load_error_strings();
        SSL_library_init();
        
        CRYPTO_thread_setup();
#endif
        
        /* Not used, as said in the 1.0.2 documentation note
        CRYPTO_set_dynlock_create_callback(demo_create);
        CRYPTO_set_dynlock_lock_callback(demo_lock);
        CRYPTO_set_dynlock_destroy_callback(demo_destroy);
         */

        ctx = SSL_CTX_new(DTLSv1_2_client_method());
        if (ctx == nullptr) throw std::runtime_error("SSL_CTX_new failed");
    }
    
    SSLEngineClientOpenSSL::~SSLEngineClientOpenSSL() {
        CRYPTO_thread_cleanup();
        SSL_CTX_free(ctx);
    }
    
    static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
        /* OpenSSL's default verification logic returns errors on self-signed certificates */
        X509* crt = X509_STORE_CTX_get_current_cert(ctx);
        if (preverify_ok == 0) {
            int err = X509_STORE_CTX_get_error(ctx);
#ifdef OSSL_SSL_DEBUG_PRINTS
            printf("error: %d (if 19, might be root CA!)\n", err);
#endif
            // 18: X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT);
            // 19: X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN (root CAs count!)
            if (err == 18 || err == 19) preverify_ok = 1;
        }
        
        return preverify_ok;
    }
    
    void SSLEngineClientOpenSSL::configure() {
#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "OpenSSL :: configure()" << std::endl;
        std::cout.flush();
#endif

        int ret = SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        
        SSL_CTX_set_ecdh_auto(ctx, 1);
        
        ret = SSL_CTX_set_cipher_list(ctx, cipher.data());
        if (ret != 1) throw std::runtime_error("set_cipher_list failed");
        
#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "set verify now" << std::endl;
        std::cout.flush();
#endif
        
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, &verify_callback); // for ease of testing

#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "load SENG server CA certificate" << std::endl;
        std::cout.flush();
#endif
        
        // Pin to self-signed SENG Server (CA) certificate!
        ret = SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr);
        if (ret != 1) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("Failed to load SENG server certificate");
        }
        
#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "Going to call create_key_and_x509()" << std::endl;
        std::cout.flush();
#endif
        
        uint8_t der_key[4096], der_cert[8192];
        int key_len {sizeof(der_key)}, cert_len {sizeof(der_cert)};
        create_key_and_x509(der_key, &key_len, der_cert, &cert_len,
                            &my_ra_tls_options);
        
#ifdef OSSL_SSL_DEBUG_PRINTS
        std::cout << "After RSA key and x509 generation" << std::endl;
        std::cout.flush();
#endif
        
        ret = SSL_CTX_use_certificate_ASN1(ctx, cert_len, der_cert);
        //ret = SSL_CTX_use_certificate(ctx, &cli_cert);
        if (ret != 1) throw std::runtime_error("use_certificate_ASN1 failed");

#ifdef USE_ECDSA
        // type 408
        ret = SSL_CTX_use_PrivateKey_ASN1(NID_X9_62_id_ecPublicKey, ctx, der_key, key_len);
        if (ret != 1) {
            printf("Failed to load EC key\n");
            throw std::runtime_error("use_PrivateKey_ASN1 failed");
        }
#else
        ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, der_key, key_len);
        //ret = SSL_CTX_use_RSAPrivateKey(ctx, &cli_rsa);
        if (ret != 1) throw std::runtime_error("use_RSAPrivateKey_ASN1 failed");
#endif

        ret = SSL_CTX_check_private_key(ctx); // check that cert and RSA priv. key are consistent!
        if (ret != 1) throw std::runtime_error("check_private_key failed");
    }
}
