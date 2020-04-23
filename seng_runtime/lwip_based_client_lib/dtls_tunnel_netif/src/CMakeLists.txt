set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/../cmake" ${CMAKE_MODULE_PATH})

find_package(MBEDTLS REQUIRED)

find_package(AttesterLib REQUIRED)
find_package(ChallengerLib REQUIRED)

find_package(AttesterLibOpenSSL REQUIRED)
find_package(ChallengerLibOpenSSL REQUIRED)

# using a modified one of the CMake 3.12.1 repo version
find_package(CURL REQUIRED)

find_package(OpenSSL REQUIRED SSL Crypto)

find_package(Protobuf-c REQUIRED)

find_package(Protobuf REQUIRED) # the C++ one

if (NOT DEFINED SGX_SDK)
set(SGX_SDK /opt/intel/sgxsdk)
endif()

set(SGX_ARCH x64)
#set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(SGX_MODE HW CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")
include (../cmake/ConfigSGX.cmake)

############################################

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS seng.proto)

add_library(seng_mbench_ossl_double_tunnel_netif
        ra_tls_options.c
        DT_RaSSLTunnelNetif_OpenSSL.cpp ../include/DT_RaSSLTunnelNetif_OpenSSL.hpp
        DT_SSLEngineClient_OpenSSL.cpp ../include/DT_SSLEngineClient_OpenSSL.hpp
        ${PROTO_SRCS} ${PROTO_HDRS}
        ../include/hooks/sockets.hpp # for seng_socket
        th-lock.c ../include/th-lock.h # multi-threading
        )

target_link_options(seng_mbench_ossl_double_tunnel_netif PRIVATE "LINKER:--exclude-libs,ALL")
target_compile_definitions(seng_mbench_ossl_double_tunnel_netif PRIVATE MEASURE_FINE_GRAINED_SETUP_TIME)

target_link_libraries(seng_mbench_ossl_double_tunnel_netif PRIVATE ${ATTESTER_LIBRARY_OPENSSL}
${CHALLENGER_LIBRARY_OPENSSL})
# we don't need to link, bcs. we only need some of the headers (sgx_quote.h -> _report.h -> key.h -> attributes.h)
#target_link_libraries(seng_tunnel_netif PRIVATE ${SGXSDK_LIBRARIES})

# TODO: link static variant of OpenSSL? (and used exclude-libs option to avoid exposing symbols)
target_link_libraries(seng_mbench_ossl_double_tunnel_netif PRIVATE CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto)
target_link_libraries(seng_mbench_ossl_double_tunnel_netif PRIVATE ${PROTOBUF-C_LIBRARIES})

target_link_libraries(seng_mbench_ossl_double_tunnel_netif PUBLIC lwip ${LIBPTHREAD})

target_link_libraries(seng_mbench_ossl_double_tunnel_netif PRIVATE protobuf::libprotobuf)


target_include_directories(seng_mbench_ossl_double_tunnel_netif PRIVATE ${ATTESTER_INCLUDE_DIRS_OPENSSL})
target_include_directories(seng_mbench_ossl_double_tunnel_netif PRIVATE ${CHALLENGER_INCLUDE_DIRS})
target_include_directories(seng_mbench_ossl_double_tunnel_netif PRIVATE ${SGXSDK_INCLUDE_DIRS})
# target_include_directories(seng_mbench_ossl_double_tunnel_netif PRIVATE ${CURL_INCLUDE_DIRS})
target_include_directories(seng_mbench_ossl_double_tunnel_netif PRIVATE ${PROTOBUF-C_INCLUDE_DIRS})

target_include_directories(seng_mbench_ossl_double_tunnel_netif PUBLIC ${LWIP_INCLUDE_DIRS})
target_include_directories(seng_mbench_ossl_double_tunnel_netif PUBLIC ../include/)

# for protobuf header
target_include_directories(seng_mbench_ossl_double_tunnel_netif PUBLIC ${CMAKE_CURRENT_BINARY_DIR})


################################################################################

add_library(seng_ossl_double_tunnel_netif
        ra_tls_options.c
        DT_RaSSLTunnelNetif_OpenSSL.cpp ../include/DT_RaSSLTunnelNetif_OpenSSL.hpp
        DT_SSLEngineClient_OpenSSL.cpp ../include/DT_SSLEngineClient_OpenSSL.hpp
        ${PROTO_SRCS} ${PROTO_HDRS}
        ../include/hooks/sockets.hpp # for seng_socket
        th-lock.c ../include/th-lock.h # multi-threading
        )

target_link_options(seng_ossl_double_tunnel_netif PRIVATE "LINKER:--exclude-libs,ALL")

target_link_libraries(seng_ossl_double_tunnel_netif PRIVATE ${ATTESTER_LIBRARY_OPENSSL}
${CHALLENGER_LIBRARY_OPENSSL})
# we don't need to link, bcs. we only need some of the headers (sgx_quote.h -> _report.h -> key.h -> attributes.h)
#target_link_libraries(seng_tunnel_netif PRIVATE ${SGXSDK_LIBRARIES})
target_link_libraries(seng_ossl_double_tunnel_netif PRIVATE CURL::libcurl
        OpenSSL::SSL
        OpenSSL::Crypto)
target_link_libraries(seng_ossl_double_tunnel_netif PRIVATE ${PROTOBUF-C_LIBRARIES})

target_link_libraries(seng_ossl_double_tunnel_netif PUBLIC lwip ${LIBPTHREAD})

target_link_libraries(seng_ossl_double_tunnel_netif PRIVATE protobuf::libprotobuf)


target_include_directories(seng_ossl_double_tunnel_netif PRIVATE ${ATTESTER_INCLUDE_DIRS_OPENSSL})
target_include_directories(seng_ossl_double_tunnel_netif PRIVATE ${CHALLENGER_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_netif PRIVATE ${SGXSDK_INCLUDE_DIRS})
# target_include_directories(seng_ossl_double_tunnel_netif PRIVATE ${CURL_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_netif PRIVATE ${PROTOBUF-C_INCLUDE_DIRS})

target_include_directories(seng_ossl_double_tunnel_netif PUBLIC ${LWIP_INCLUDE_DIRS})
target_include_directories(seng_ossl_double_tunnel_netif PUBLIC ../include/)

# for protobuf header
target_include_directories(seng_ossl_double_tunnel_netif PUBLIC ${CMAKE_CURRENT_BINARY_DIR})


################################################################################

find_package(Doxygen
        REQUIRED dot
        OPTIONAL_COMPONENTS mscgen dia)

set(DOXYGEN_EXTRACT_ALL YES)

doxygen_add_docs(seng_tunnel_netif_docs
        ../
        COMMENT "DTLS Netif Documentation")

################################################################################

add_library(seng_ossl_double_onload
        DT_OnLoadSENGStarter_OpenSSL.cpp ../include/DT_OnLoadSENGStarter_OpenSSL.hpp
        PreloadHooker.cpp ../include/PreloadHooker.hpp

        ../include/hooks/getinfo.hpp  ../include/hooks/polling.hpp  ../include/hooks/receiving.hpp  ../include/hooks/sending.hpp  ../include/hooks/sockctrl.hpp  ../include/hooks/sockets.hpp
        hooks/getinfo.cpp  hooks/polling.cpp  hooks/receiving.cpp  hooks/sending.cpp  hooks/sockctrl.cpp  hooks/sockets.cpp
        ../include/HookCommons.hpp

        hooks/listen_shadow.cpp ../include/hooks/listen_shadow.hpp

        ${PROTO_SRCS} ${PROTO_HDRS}
        )

if (SENG_AUTO_NAT)
    target_compile_definitions(seng_ossl_double_onload PRIVATE ENABLE_LISTEN_MECHANISM)
endif()

target_link_libraries(seng_ossl_double_onload PRIVATE lwip seng_ossl_double_tunnel_netif)
target_link_libraries(seng_ossl_double_onload PRIVATE protobuf::libprotobuf)
target_link_libraries(seng_ossl_double_onload PRIVATE ${CMAKE_DL_LIBS})

target_include_directories(seng_ossl_double_onload PRIVATE
        ${LWIP_INCLUDE_DIRS}
        ../include/
        )

# for protobuf header
target_include_directories(seng_ossl_double_onload PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

################################################################################

add_library(seng_ossl_double_onload_finegrained_mbench
        DT_OnLoadSENGStarter_OpenSSL.cpp ../include/DT_OnLoadSENGStarter_OpenSSL.hpp
        PreloadHooker.cpp ../include/PreloadHooker.hpp

        ../include/hooks/getinfo.hpp  ../include/hooks/polling.hpp  ../include/hooks/receiving.hpp  ../include/hooks/sending.hpp  ../include/hooks/sockctrl.hpp  ../include/hooks/sockets.hpp
        hooks/getinfo.cpp  hooks/polling.cpp  hooks/receiving.cpp  hooks/sending.cpp  hooks/sockctrl.cpp  hooks/sockets.cpp
        ../include/HookCommons.hpp

        hooks/listen_shadow.cpp ../include/hooks/listen_shadow.hpp

        ${PROTO_SRCS} ${PROTO_HDRS}
        )

if (SENG_AUTO_NAT)
        target_compile_definitions(seng_ossl_double_onload_finegrained_mbench PRIVATE ENABLE_LISTEN_MECHANISM
                          PRIVATE MEASURE_NETIF_SETUP_TIME
                          PRIVATE MEASURE_FINE_GRAINED_SETUP_TIME
                          PRIVATE MEASURE_LISTEN_TIME)
else()
        target_compile_definitions(seng_ossl_double_onload_finegrained_mbench
                          PRIVATE MEASURE_NETIF_SETUP_TIME
                          PRIVATE MEASURE_FINE_GRAINED_SETUP_TIME
                          PRIVATE MEASURE_LISTEN_TIME)
endif()

target_link_libraries(seng_ossl_double_onload_finegrained_mbench PRIVATE lwip seng_mbench_ossl_double_tunnel_netif)
target_link_libraries(seng_ossl_double_onload_finegrained_mbench PRIVATE protobuf::libprotobuf)
target_link_libraries(seng_ossl_double_onload_finegrained_mbench PRIVATE ${CMAKE_DL_LIBS})

target_include_directories(seng_ossl_double_onload_finegrained_mbench PRIVATE
        ${LWIP_INCLUDE_DIRS}
        ../include/
        )

# for protobuf header
target_include_directories(seng_ossl_double_onload_finegrained_mbench PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

################################################################################

add_library(app_bench_onload
        bench_app_thread/OnLoadAppBench.cpp
        ../include/bench_app_thread/OnLoadAppBench.hpp
        )

target_include_directories(app_bench_onload PRIVATE
        ../include/
        )

