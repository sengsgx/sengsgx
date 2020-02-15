find_path(ATTESTER_INCLUDE_DIRS ra.h mbedtls-ra-attester.h
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../sgx-ra-tls/")

find_library(ATTESTER_LIBRARY mbedtls/libnonsdk-ra-attester.a
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../sgx-ra-tls/")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ATTESTER DEFAULT_MSG
        ATTESTER_INCLUDE_DIRS ATTESTER_LIBRARY)

mark_as_advanced(ATTESTER_INCLUDE_DIRS ATTESTER_LIBRARY)
