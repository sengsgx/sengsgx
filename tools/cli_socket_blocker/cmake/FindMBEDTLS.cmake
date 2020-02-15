# https://github.com/Kitware/CMake/blob/master/Utilities/cmcurl/CMake/FindMbedTLS.cmake
find_path(MBEDTLS_INCLUDE_DIRS mbedtls/ssl.h
HINTS "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-2.16.1/build/built_stuff/include/")

find_library(MBEDTLS_LIBRARY mbedtls
HINTS "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-2.16.1/build/built_stuff/lib/")
find_library(MBEDX509_LIBRARY mbedx509
HINTS "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-2.16.1/build/built_stuff/lib/")
find_library(MBEDCRYPTO_LIBRARY mbedcrypto
HINTS "${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-2.16.1/build/built_stuff/lib/")

set(MBEDTLS_LIBRARIES "${MBEDTLS_LIBRARY}" "${MBEDX509_LIBRARY}" "${MBEDCRYPTO_LIBRARY}")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MBEDTLS DEFAULT_MSG
        MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)

mark_as_advanced(MBEDTLS_INCLUDE_DIRS MBEDTLS_LIBRARY MBEDX509_LIBRARY MBEDCRYPTO_LIBRARY)
