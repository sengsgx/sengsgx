set(LWIP_COMPILER_FLAGS_GNU_CLANG
    -g
    -Wall
#    -pedantic # doesn't like SGX SDK libs
    -Werror
    -Wparentheses
    -Wsequence-point
    -Wswitch-default
    -Wextra -Wundef
    -Wshadow
    -Wpointer-arith
    -Wcast-qual
    -Wc++-compat
    -Wwrite-strings
    -Wold-style-definition
    -Wcast-align
    -Wmissing-prototypes
#    -Wnested-externs # getting it for print and fflush; not sure why/whether a big deal
    -Wunreachable-code
    -Wuninitialized
    -Wmissing-prototypes
    -Waggregate-return
    -Wlogical-not-parentheses
)

list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
-Wredundant-decls
)

if(CMAKE_C_COMPILER_ID STREQUAL GNU)
    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
        -Wlogical-op
        -Wtrampolines
    )

#    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
#        -Wc90-c99-compat  # doesn't like SGX SDK libs
#    )

    if(NOT CMAKE_C_COMPILER_VERSION VERSION_LESS 4.9)
        if(LWIP_USE_SANITIZERS)
            list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
                -fsanitize=address
                -fsanitize=undefined
                -fno-sanitize=alignment
                -fstack-protector
                -fstack-check
            )
            set(LWIP_SANITIZER_LIBS asan ubsan)
        endif()
    endif()

    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS_GNU_CLANG})
endif()

if(CMAKE_C_COMPILER_ID STREQUAL Clang)
    list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
        -Wdocumentation
        -Wno-documentation-deprecated-sync
    )

    if(LWIP_USE_SANITIZERS)
        list(APPEND LWIP_COMPILER_FLAGS_GNU_CLANG
            -fsanitize=address
            -fsanitize=undefined
            -fno-sanitize=alignment
        )
        set(LWIP_SANITIZER_LIBS asan ubsan)
    endif()

    set(LWIP_COMPILER_FLAGS ${LWIP_COMPILER_FLAGS_GNU_CLANG})
endif()

if(CMAKE_C_COMPILER_ID STREQUAL MSVC)
    # TODO
endif()
