set(APP_ENC_SRCS
    app_enclave.cpp app_enclave.h)
set(APP_ENC_LDS app_enclave.lds)

add_enclave_library(app_enclave SRCS ${APP_ENC_SRCS}
    EDL app_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS} LDSCRIPT ${APP_ENC_LDS}
    ADD_CXX_FLAGS "-g -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security -std=c++11 -nostdinc++"
    EDL_INCLUDE_DIRS ${RATLS_INCLUDE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/../../seng/include/")

target_link_libraries(app_enclave seng_truntime)

# for "ra.h" included in EDL file of external/sgx-ra-tls
target_include_directories(app_enclave
    PRIVATE ${RATLS_INCLUDE_DIR}
)

target_compile_options(app_enclave PUBLIC
    "-g" "-nostdinc" "-fvisibility=hidden" "-fpic" "-fpie" "-fstack-protector"
    "-fno-builtin-printf" "-Wformat" "-Wformat-security" "-Wno-implicit-function-declaration"
    "-std=c11" "-std=c++11" "-nostdinc++")


enclave_sign(app_enclave KEY app_enclave_private.pem CONFIG app_enclave.config.xml)
