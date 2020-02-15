find_library(LINUXLWIP_LIBRARY liblwip.so
        HINTS "${PROJECT_SOURCE_DIR}/externals/lwip/contrib/ports/unix/lib/build/")

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LINUXLWIP DEFAULT_MSG LINUXLWIP_LIBRARY)

mark_as_advanced(LINUXLWIP_LIBRARY)
