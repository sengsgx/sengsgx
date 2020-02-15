cmake_minimum_required(VERSION 3.7)
project(seng_server
        LANGUAGES C CXX
        VERSION 1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

if (NOT DEFINED SGX_SDK)
        set(SGX_SDK /opt/intel/sgxsdk)
endif()
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/ConfigSGX.cmake)

add_subdirectory(src)
