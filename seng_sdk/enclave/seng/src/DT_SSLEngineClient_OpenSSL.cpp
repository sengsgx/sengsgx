#include "DT_SSLEngineClient_OpenSSL.hpp"

#include <stdexcept>
#include <cassert>
#include <iostream>

#include "seng_utils.h"

#include <sgx_quote.h>

extern "C" {
    #include "ra-attester.h"
}

//#define SSLENG_DEBUG

namespace seng {
    SSLEngineClientOpenSSL::SSLEngineClientOpenSSL(std::string cipher_str) :
    cipher(cipher_str) {

        SSL_load_error_strings();
        SSL_library_init();
        
        ctx = SSL_CTX_new(DTLS_client_method());
        if (ctx == nullptr) throw std::runtime_error("SSL_CTX_new failed");
    }
    
    SSLEngineClientOpenSSL::~SSLEngineClientOpenSSL() {
        SSL_CTX_free(ctx);
    }

    void SSLEngineClientOpenSSL::configure() {
        int ret = SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
        
        SSL_CTX_set_ecdh_auto(ctx, 1);
        
        ret = SSL_CTX_set_cipher_list(ctx, cipher.data());
        if (ret != 1) throw std::runtime_error("set_cipher_list failed");
   
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        //SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, &verify_callback); // for ease of testing

        // Pin to self-signed SENG Server (CA) certificate!
#ifdef SSLENG_DEBUG
        printf("[Enclave] Get Cert Store\n");
#endif
        X509_STORE *cacert_store = SSL_CTX_get_cert_store(ctx);
        if (cacert_store == nullptr) throw std::runtime_error("Getting (CA) Cert Store failed");

        //TODO: add mechanism to securely fetch from disk instead
        X509 *ngw_cert;
        const char *ngw_hc_cert = "-----BEGIN CERTIFICATE-----\nADD_YOURS\n-----END CERTIFICATE-----";

#ifdef SSLENG_DEBUG
        printf("[Enclave] Create BIO mem\n");
#endif
        BIO *mem = BIO_new(BIO_s_mem());
        if (mem == nullptr) throw std::runtime_error("Failed to create mem BIO");

#ifdef SSLENG_DEBUG
        printf("[Enclave] Connect BIO mem\n");
#endif
        ret = BIO_puts(mem, ngw_hc_cert);
        if (ret <= 0) throw std::runtime_error("Failed to fill mem buffer with cert");

#ifdef SSLENG_DEBUG
        printf("[Enclave] Read PEM X509 certificate from mem buffer\n");
#endif
        ngw_cert = PEM_read_bio_X509(mem, nullptr, 0, nullptr);
        if (ngw_cert == nullptr) throw std::runtime_error("Failed to parse X509 cert");

#ifdef SSLENG_DEBUG
        printf("[Enclave] Free mem BIO\n");
#endif
        ret = BIO_free(mem);
        if (ret != 1) throw std::runtime_error("Failed to free mem BIO");

#ifdef SSLENG_DEBUG
        printf("[Enclave] Add NGW Certificate to Context\n");
#endif
        ret = X509_STORE_add_cert(cacert_store, ngw_cert);
        if (ret != 1) throw std::runtime_error("Failed to set hard-coded Middlebox CA Certifciate\n");


        // Generate RSA key-pair, craft X.509 certificate (later: remote attest, add report to certificate)
        uint8_t der_key[4096], der_cert[8192];
        int key_len {sizeof(der_key)}, cert_len {sizeof(der_cert)};

#ifdef SSLENG_DEBUG
        printf("[Enclave] Calling create_key_and_x509() function\n");
#endif
        create_key_and_x509(der_key, &key_len, der_cert, &cert_len,
                            &my_ra_tls_options);
#ifdef SSLENG_DEBUG
        printf("[Enclave] gen function returned\n");
#endif

        // add cert + private RSA key to context and call consistency-check function
        ret = SSL_CTX_use_certificate_ASN1(ctx, cert_len, der_cert);
        //ret = SSL_CTX_use_certificate(ctx, &cli_cert);
        if (ret != 1) throw std::runtime_error("use_certificate_ASN1 failed");

        ret = SSL_CTX_use_RSAPrivateKey_ASN1(ctx, der_key, key_len);
        //ret = SSL_CTX_use_RSAPrivateKey(ctx, &cli_rsa);
        if (ret != 1) throw std::runtime_error("use_RSAPrivateKey_ASN1 failed");
        
        ret = SSL_CTX_check_private_key(ctx); // check that cert and RSA priv. key are consistent!
        if (ret != 1) throw std::runtime_error("check_private_key failed");
    }
}
