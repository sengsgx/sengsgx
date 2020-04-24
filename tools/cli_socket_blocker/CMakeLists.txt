cmake_minimum_required(VERSION 3.10)
project(client_socket_blocker
        LANGUAGES C CXX
        VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

find_package(MBEDTLS REQUIRED)
find_package(Protobuf REQUIRED) # the C++ one

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS seng.proto)

if (NOT DEFINED SGX_SDK)
    set(SGX_SDK /opt/intel/sgxsdk)
endif()
set(SGX_ARCH x64)
set(SGX_MODE SIM CACHE STRING "SGX mode: SIM or HW") # SGX mode: sim, hw
set(COMPILE_EXAMPLES NO CACHE BOOL "Build examples")
set(SGX_BUILD DEBUG CACHE STRING "Build: DEBUG, PRERELEASE or RELEASE")

include (cmake/ConfigSGX.cmake)

add_executable(cli_sock_blocker
        CliSockBlocker.cpp
        SSLEngine.cpp SSLEngine.hpp
        ${PROTO_SRCS} ${PROTO_HDRS}
        )

target_link_libraries(cli_sock_blocker PRIVATE ${MBEDTLS_LIBRARIES})
target_link_libraries(cli_sock_blocker PRIVATE protobuf::libprotobuf)


target_include_directories(cli_sock_blocker PRIVATE ${MBEDTLS_INCLUDE_DIRS})
target_include_directories(cli_sock_blocker PRIVATE ${SGXSDK_INCLUDE_DIRS})
target_include_directories(cli_sock_blocker PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

################################################################################

find_package(Doxygen
        REQUIRED dot
        OPTIONAL_COMPONENTS mscgen dia)

set(DOXYGEN_EXTRACT_ALL YES)

doxygen_add_docs(cli_sock_blocker_docs
        ../
        COMMENT "Client Socket Blocker  Documentation")
