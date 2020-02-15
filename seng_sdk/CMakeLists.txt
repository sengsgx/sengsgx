cmake_minimum_required(VERSION 3.7)
project(seng_sdk_library
    LANGUAGES C CXX
    VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set (BUILD_SHARED_LIBS OFF)

# Path to custom CMake Modules
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

# SGX Configuration
#if (NOT DEFINED SGX_SDK)
#set(SGX_SDK /opt/intel/sgxsdk)
#endif()

#set(SGX_ARCH x64)
#set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
#set(SGX_MODE HW CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
#set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")
#include (cmake/ConfigSGX.cmake)

#set(SGX_HW ON)
find_package(SGX REQUIRED)
message("SGX_FOUND: ${SGX_FOUND}")

set(PATH_TO_SSL "${CMAKE_SOURCE_DIR}/external/sgxssl/Linux")

# lwIP, SGX-SSL, sgx-ra-tls
add_subdirectory(external)

if(NOT (DEFINED LWIP_INCLUDE_DIRS AND DEFINED SGXSSL_USSL_LIB))
    message(FATAL_ERROR "Something went wrong with configuration of lwIP and/or SGX-SSL")
endif()

# SENG Client Runtime Library
set(EDL_SEARCH_PATHS "${CMAKE_CURRENT_SOURCE_DIR}/enclave/seng/include"
    ${SGXSSL_INCLUDE_DIR}
    ${RATLS_INCLUDE_DIR}
    "${SENG_LWIP_PORT_DIR}/include")
add_subdirectory(enclave)
add_subdirectory(app)
