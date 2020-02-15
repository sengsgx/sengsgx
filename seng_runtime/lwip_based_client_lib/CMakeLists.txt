cmake_minimum_required(VERSION 3.7)
project(lwip_demo_app
        LANGUAGES C CXX
        VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set (BUILD_SHARED_LIBS ON)

set (LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/externals/lwip)
set (LWIP_CONTRIB_DIR ${LWIP_DIR}/contrib)
include(${LWIP_DIR}/contrib/ports/CMakeCommon.cmake)

set (LWIP_DEFINITIONS -DLWIP_DEBUG)
set (LWIP_INCLUDE_DIRS
    "${LWIP_DIR}/src/include"
    "${LWIP_CONTRIB_DIR}/"
    "${LWIP_CONTRIB_DIR}/ports/unix/port/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
)

include(${LWIP_CONTRIB_DIR}/ports/unix/Filelists.cmake)
include(${LWIP_DIR}/src/Filelists.cmake)

add_library(lwip include/lwipopts.h
        ${lwipcore_SRCS} ${lwipcore4_SRCS} ${lwipapi_SRCS}
        ${lwipcontribportunix_SRCS}
        )

# only required for TCP WIN sizes > 131KB in lwIP config
target_compile_options(lwip PRIVATE ${LWIP_COMPILER_FLAGS} "-Wno-error=type-limits")

target_compile_definitions(lwip PRIVATE ${LWIP_DEFINITIONS} ${LWIP_MBEDTLS_DEFINITIONS})
target_include_directories(lwip PRIVATE ${LWIP_INCLUDE_DIRS} ${LWIP_MBEDTLS_INCLUDE_DIRS})
target_link_libraries(lwip ${LWIP_SANITIZER_LIBS})

find_library(LIBPTHREAD pthread REQUIRED)
target_link_libraries(lwip ${LIBPTHREAD})

add_subdirectory(dtls_tunnel_netif)

