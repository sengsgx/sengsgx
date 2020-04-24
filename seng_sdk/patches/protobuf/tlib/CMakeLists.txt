# source: https://github.com/light1021/protobuf-c/blob/sgx/build-cmake/tlib/CMakeLists.txt
SET(SGX_SDK /opt/intel/sgxsdk)
SET(SGX_LIBRARY_PATH ${SGX_SDK}/lib64)
INCLUDE_DIRECTORIES(${SGX_SDK}/include ${SGX_SDK}/include/tlibc ${SGX_SDK}/include/libcxx)

SET(CMAKE_C_FLAGS "-fPIC -nostdinc ")

ADD_LIBRARY(tprotobuf-c ${PC_SOURCES})
