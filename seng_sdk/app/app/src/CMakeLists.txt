set(SRCS app.cpp)
add_untrusted_executable(DemoApp SRCS ${SRCS}
    EDL ../../../enclave/app/src/app_enclave.edl EDL_SEARCH_PATHS ${EDL_SEARCH_PATHS}
)
add_dependencies(DemoApp enclave-sign)
target_link_libraries(DemoApp seng_uruntime)
target_include_directories(DemoApp PRIVATE 
    ${RATLS_INCLUDE_DIR})