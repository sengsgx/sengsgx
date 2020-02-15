find_path(CHALLENGER_INCLUDE_DIRS ra.h ra-challenger.h
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../sgx-ra-tls/")

find_library(CHALLENGER_LIBRARY_OPENSSL openssl/libra-challenger.a
        HINTS "${CMAKE_CURRENT_SOURCE_DIR}/../../../../sgx-ra-tls/")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CHALLENGER DEFAULT_MSG
        CHALLENGER_INCLUDE_DIRS CHALLENGER_LIBRARY_OPENSSL)

mark_as_advanced(CHALLENGER_INCLUDE_DIRS CHALLENGER_LIBRARY_OPENSSL)
