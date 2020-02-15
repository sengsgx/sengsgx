#ifndef SENG_SSLENGINE_OPENSSL_HPP
#define SENG_SSLENGINE_OPENSSL_HPP

#include <string>

#include <openssl/ssl.h>


namespace seng {
    struct SSLEngineOpenSSL {
        SSL_CTX *ctx;
        std::string cipher;
        
        SSLEngineOpenSSL(std::string cipher);
        ~SSLEngineOpenSSL();

        void configure(std::string cert_file_path,
                       std::string key_file_path);
    };
}

#endif /* SENG_SSLENGINE_OPENSSL_HPP */
