find_package(LibUV REQUIRED)
find_package(MBEDTLS REQUIRED)
find_package(ChallengerLibOpenSSL REQUIRED)
find_package(Protobuf REQUIRED)
find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

# TODO: add as subrepo! / via Docker container!
set(OPENSSL_ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../compiled_openssl_1_0_2g/")
find_package(OpenSSL REQUIRED SSL Crypto)

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS seng.proto)

add_executable(seng_ossl_double_tunnel_server
        SengMain_adapted.cpp ../include/SengMain_adapted.hpp
        SengServer_OpenSSL.cpp ../include/SengServer_OpenSSL.hpp
        SSLEngine_OpenSSL.cpp ../include/SSLEngine_OpenSSL.hpp
        SSLEngine.cpp ../include/SSLEngine.hpp # for shadow server
        TunnelToEnclave_OpenSSL.cpp ../include/TunnelToEnclave_OpenSSL.hpp
        PacketForwarder_adapted.cpp ../include/PacketForwarder_adapted.hpp
        OpenSSLUVCallbacks.cpp ../include/OpenSSLUVCallbacks.hpp
        EncIdxBase.cpp ../include/EncIdxBase.hpp
        EnclaveSqlite3Index.cpp ../include/EnclaveSqlite3Index.hpp
        EnclaveIndex_adapted.cpp ../include/EnclaveIndex_adapted.hpp
        enc_srv_socks/ClientSocketShadower_adapted.cpp ../include/enc_srv_socks/ClientSocketShadower_adapted.hpp
        enc_srv_socks/ShadowRule.cpp ../include/enc_srv_socks/ShadowRule.hpp
        ${PROTO_SRCS} ${PROTO_HDRS})

target_link_libraries(seng_ossl_double_tunnel_server PRIVATE LibUV::LibUV)
target_link_libraries(seng_ossl_double_tunnel_server PRIVATE ${CHALLENGER_LIBRARY_OPENSSL}
        OpenSSL::SSL
        OpenSSL::Crypto
        ${CMAKE_DL_LIBS})
target_link_libraries(seng_ossl_double_tunnel_server PRIVATE ${MBEDTLS_LIBRARIES}) # shadow server
# we only need the headers, not the lib (sgx_quote.h -> _report.h -> _key.h -> _attributes.h)
#target_link_libraries(seng_tunnel_server PRIVATE ${SGXSDK_LIBRARIES})
target_link_libraries(seng_ossl_double_tunnel_server PRIVATE protobuf::libprotobuf)
target_link_libraries(seng_ossl_double_tunnel_server PRIVATE Threads::Threads)
target_link_libraries(seng_ossl_double_tunnel_server PRIVATE ${SQLite3_LIBRARIES})

target_include_directories(seng_ossl_double_tunnel_server PUBLIC ../include)

target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${LibUV_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${MBEDTLS_INCLUDE_DIRS}) # shadow server
target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${SGXSDK_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${CHALLENGER_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${SQLite3_INCLUDE_DIRS})
# otherwise does not find the PROTO_HDRS
target_include_directories(seng_ossl_double_tunnel_server PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

################################################################################
find_package(Doxygen
        REQUIRED dot
        OPTIONAL_COMPONENTS mscgen dia)

set(DOXYGEN_EXTRACT_ALL YES)

doxygen_add_docs(seng_double_tunnel_docs
        ../
        COMMENT "SENG Server Documentation")
