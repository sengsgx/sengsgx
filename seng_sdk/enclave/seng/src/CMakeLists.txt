set(SENG_SRCS
    DT_SSLEngineClient_OpenSSL.cpp DT_SSLEngineClient_OpenSSL.hpp
    ra_tls_options.c
    seng_tunnelmodule.cpp seng_tunnelmodule.hpp
    seng.pb-c.c seng.pb-c.h
    seng_utils.cpp ../include/seng_utils.h
    seng_api.cpp ../include/seng_api.hpp
    )
set(SENG_LDS seng.lds)

add_trusted_library(seng_truntime SRCS ${SENG_SRCS}
#OTHER_LIBS "-Wl,--whole-archive ${SGXSSL_TSSL_LIB} -Wl,--no-whole-archive -Wl,--whole-archive ${SGXSSL_OSSL_TTLS_LIB} -Wl,--no-whole-archive ${SGXSSL_TCRYPT_LIB}"
    OTHER_LIBS "-Wl,--start-group ${SGXSSL_TSSL_LIB} ${SGXSSL_OSSL_TTLS_LIB} ${SGXSSL_TCRYPT_LIB} -Wl,--end-group"
    EDL "../include/seng.edl" EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${SENG_LDS}
    ADD_CXX_FLAGS "-nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -std=c++11 -nostdinc++"
    EDL_INCLUDE_DIRS ${RATLS_INCLUDE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_options(seng_truntime PUBLIC
    "-nostdinc" "-fvisibility=hidden" "-fpic" "-fpie" "-fstack-protector"
    "-fno-builtin-printf" "-Wformat" "-Wformat-security" "-Wno-implicit-function-declaration"
    "-std=c11" "-std=c++11" "-nostdinc++")

target_include_directories(seng_truntime
    PUBLIC ${SGXSSL_INCLUDE_DIR}
    PUBLIC ${RATLS_INCLUDE_DIR}
    PRIVATE ${PROTOC_C_INC}
    PUBLIC ${LWIP_INCLUDE_DIRS}
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

target_link_libraries(seng_truntime ratls_ossl_trusted)
target_link_libraries(seng_truntime tprotobuf-c)
target_link_libraries(seng_truntime lwip)
