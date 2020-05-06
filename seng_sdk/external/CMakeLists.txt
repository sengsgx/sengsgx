# Build lwIP static library
set (LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)
set (LWIP_CONTRIB_DIR ${LWIP_DIR}/contrib)
include(${CMAKE_CURRENT_SOURCE_DIR}/seng_lwip_port/CMakeCommon.cmake)

set(SENG_LWIP_PORT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/seng_lwip_port/")
set(SENG_LWIP_PORT_DIR "${SENG_LWIP_PORT_DIR}" PARENT_SCOPE)

set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    #"${LWIP_CONTRIB_DIR}/"
#    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/seng_lwip_port/include"
    # custom config file
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)
# export for later include
set (LWIP_INCLUDE_DIRS ${LWIP_INCLUDE_DIRS} PARENT_SCOPE)

#include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/seng_lwip_port/Filelists.cmake)
include(${LWIP_DIR}/src/Filelists.cmake)

add_library(lwip include/lwipopts.h
        ${lwipcore_SRCS} ${lwipcore4_SRCS} ${lwipapi_SRCS}
#        ${lwipcontribportunix_SRCS}
        ${lwipcontribportseng_SRCS}
)

# only required for TCP WIN sizes > 131KB in lwIP config
target_compile_options(lwip PRIVATE
    ${LWIP_COMPILER_FLAGS} "-Wno-error=type-limits"
    "-nostdinc" "-fvisibility=hidden" "-fpic" "-fpie" "-fstack-protector"
    "-fno-builtin-printf" "-Wformat" "-Wformat-security" "-Wno-implicit-function-declaration"
    "-std=c11")

message("LWIP_COMPILER_FLAGS: ${LWIP_COMPILER_FLAGS}")

target_compile_definitions(lwip PRIVATE ${LWIP_DEFINITIONS})
target_include_directories(lwip PRIVATE ${LWIP_INCLUDE_DIRS}
        PUBLIC ${SGX_INCLUDE_DIR}
        PUBLIC ${SGX_INCLUDE_DIR}/tlibc)
target_link_libraries(lwip ${LWIP_SANITIZER_LIBS})

#find_library(LIBPTHREAD pthread REQUIRED)
#target_link_libraries(lwip ${LIBPTHREAD})




# SGX SSL
add_custom_command(OUTPUT ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl.a
        ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl_crypto.a
        ${PATH_TO_SSL}/package/lib64/libsgx_usgxssl.a
        ${PATH_TO_SSL}/package/include/openssl
        ${PATH_TO_SSL}/package/lib64/libsgx_ttls.a
        ${PATH_TO_SSL}/sgx/libsgx_usgxssl/libsgx_usgxssl.a
        ${PATH_TO_SSL}/sgx/libsgx_tsgxssl/libsgx_tsgxssl.a
    COMMAND . ${SGX_PATH}/environment && DEBUG=0 make
    WORKING_DIRECTORY ${PATH_TO_SSL}
)

add_custom_target(sgxssl ALL
    DEPENDS ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl.a)

set(SGXSSL_TSSL_LIB ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl.a PARENT_SCOPE)
# QUESTION: Why is this not a shared library as other untrusted SDK? [maybe I configured sth. wrong?]
set(SGXSSL_USSL_LIB ${PATH_TO_SSL}/package/lib64/libsgx_usgxssl.a PARENT_SCOPE)
set(SGXSSL_TCRYPT_LIB ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl_crypto.a PARENT_SCOPE)
set(SGXSSL_INCLUDE_DIR ${PATH_TO_SSL}/package/include PARENT_SCOPE)
set(SGXSSL_OSSL_INCLUDE_DIR ${PATH_TO_SSL}/package/include/openssl PARENT_SCOPE)
set(SGXSSL_OSSL_TTLS_LIB ${PATH_TO_SSL}/package/lib64/libsgx_ttls.a PARENT_SCOPE)

set(SGXSSL_INCLUDE_DIR ${PATH_TO_SSL}/package/include)


# SDK- and OpenSSL-based sgx-ra-tls libs
set(RATLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/sgx-ra-tls)
set(RATLS_TRUSTED_DIR ${RATLS_DIR}/trusted)
set(RATLS_UNTRUSTED_DIR ${RATLS_DIR}/untrusted)
set(RATLS_INCLUDE_DIR ${RATLS_DIR}/include)
set(RATLS_EDL ${RATLS_INCLUDE_DIR}/ra_tls.edl)

# export
set(RATLS_INCLUDE_DIR ${RATLS_INCLUDE_DIR} PARENT_SCOPE)
set(RATLS_EDL ${RATLS_EDL} PARENT_SCOPE)

# Trusted Lib
add_custom_command(OUTPUT ra_tls_t.h
    COMMAND ${SGX_EDGER8R} --header-only --trusted ${RATLS_EDL} --search-path ${SGX_INCLUDE_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -std=c++11 -nostdinc++ -std=c11 -Wno-implicit-function-declaration")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -Wno-implicit-function-declaration -std=c11")

add_library(ratls_ossl_trusted STATIC
    ${RATLS_TRUSTED_DIR}/openssl-ra-attester.c
    ${RATLS_TRUSTED_DIR}/sgxsdk-ra-attester_t.c
    ${RATLS_TRUSTED_DIR}/ra-challenger.c
    ${RATLS_INCLUDE_DIR}/ra-attester.h
    ${RATLS_INCLUDE_DIR}/ra-challenger_private.h
    ${RATLS_INCLUDE_DIR}/ra.h
    ${RATLS_INCLUDE_DIR}/ra_private.h
    ${CMAKE_CURRENT_BINARY_DIR}/ra_tls_t.h
    ${RATLS_TRUSTED_DIR}/str-two-way.h)

# Target-wise spec to not interfer with our compilations
target_compile_options(ratls_ossl_trusted PUBLIC
    "-nostdinc" "-fvisibility=hidden" "-fpic" "-fpie" "-fstack-protector"
    "-fno-builtin-printf" "-Wformat" "-Wformat-security" "-Wno-implicit-function-declaration"
    "-std=c11")

message("SGX_COMMON_CFLAGS: ${SGX_COMMON_CFLAGS}")
message("SGX_INCLUDE_DIR: ${SGX_INCLUDE_DIR}")
message("SGXSSL_INCLUDE_DIR: ${SGXSSL_INCLUDE_DIR}")

target_include_directories(ratls_ossl_trusted
    PUBLIC ${RATLS_INCLUDE_DIR}
    PUBLIC ${SGX_INCLUDE_DIR}
    PUBLIC ${SGX_INCLUDE_DIR}/tlibc
    PUBLIC ${SGXSSL_INCLUDE_DIR}
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

# -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -lsgx_tcrypto -l${SGX_TSVC_LIB} -Wl,--end-group \
target_link_libraries(ratls_ossl_trusted "${SGX_COMMON_CFLAGS} \
    -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie \
    -Wl,--start-group ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl.a ${PATH_TO_SSL}/package/lib64/libsgx_tsgxssl_crypto.a -Wl,--end-group \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L${SGX_LIBRARY_PATH} \
    -Wl,--start-group -lsgx_tstdc -l${SGX_TSVC_LIB} -Wl,--end-group \
    -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
    -Wl,-pie -fpie -fpic -Wl,--export-dynamic \
    ${LDSCRIPT_FLAG} \
    -Wl,--defsym,__ImageBase=0")

# Untrusted Lib
find_package(CURL REQUIRED)

add_custom_command(OUTPUT ra_tls_u.h
    COMMAND ${SGX_EDGER8R} --header-only --untrusted ${RATLS_EDL} --search-path ${SGX_INCLUDE_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_library(ratls_untrusted SHARED
    ${RATLS_UNTRUSTED_DIR}/ias-ra.c  ${RATLS_UNTRUSTED_DIR}/sgxsdk-ra-attester_u.c
    ${RATLS_INCLUDE_DIR}/ra-attester.h
    ${RATLS_INCLUDE_DIR}/ias-ra.h
    ${RATLS_INCLUDE_DIR}/ra.h
    ${CMAKE_CURRENT_BINARY_DIR}/ra_tls_u.h)

target_include_directories(ratls_untrusted
    PUBLIC ${RATLS_INCLUDE_DIR}
    PUBLIC ${SGX_INCLUDE_DIR}
    PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(ratls_untrusted
    -L${SGX_LIBRARY_PATH} -lsgx_uae_service
    CURL::libcurl)




# Protobuf-C -- "tprotobuf-c" library
add_subdirectory(protobuf-c-1.2.1/build-cmake)
SET(PROTOC_C_INC ${PROTOC_C_INC} PARENT_SCOPE)
