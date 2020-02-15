set(lwipcontribportseng_SRCS
    ${CMAKE_CURRENT_SOURCE_DIR}/seng_lwip_port/sys_arch.c
)

add_library(lwipcontribportseng EXCLUDE_FROM_ALL ${lwipcontribportseng_SRCS})
target_include_directories(lwipcontribportseng PRIVATE ${LWIP_INCLUDE_DIRS})
target_compile_options(lwipcontribportseng PRIVATE ${LWIP_COMPILER_FLAGS})
target_compile_definitions(lwipcontribportseng PRIVATE ${LWIP_DEFINITIONS})

#if (CMAKE_SYSTEM_NAME STREQUAL Linux)
#    find_library(LIBUTIL util)
#    find_library(LIBPTHREAD pthread)
#    find_library(LIBRT rt)
#    target_link_libraries(lwipcontribportunix PUBLIC ${LIBUTIL} ${LIBPTHREAD} ${LIBRT})
#endif()

