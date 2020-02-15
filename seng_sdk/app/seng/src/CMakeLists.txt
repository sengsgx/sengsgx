add_untrusted_library(seng_uruntime SHARED
    SRCS untrusted_seng.cpp untrusted_seng.hpp
        ${SENG_LWIP_PORT_DIR}/untrusted_seng_threads.c
    EDL ../../../enclave/seng/include/seng.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
# Link untrusted library of SGX SSL
target_link_libraries(seng_uruntime ${SGXSSL_USSL_LIB} ratls_untrusted)
target_include_directories(seng_uruntime PRIVATE
    ${RATLS_INCLUDE_DIR}
    ${SENG_LWIP_PORT_DIR}/include)
