#ifndef SENG_SSLENGINE_CLIENT_OPENSSL_HPP
#define SENG_SSLENGINE_CLIENT_OPENSSL_HPP

#include <string>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

extern struct ra_tls_options my_ra_tls_options;

namespace seng {    
    struct SSLEngineClientOpenSSL {
        SSL_CTX *ctx;
        std::string cipher, ca_file;
        
        SSLEngineClientOpenSSL(std::string cipher);
        ~SSLEngineClientOpenSSL();

        void configure();
    };
}

#endif /* SENG_SSLENGINE_CLIENT_OPENSSL_HPP */
