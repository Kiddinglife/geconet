cmake_minimum_required(VERSION 3.6)
project(gecounittest)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES
        ../../unittets/test-main.cc
        ../../unittets/test-mbu.cc
        ../../unittets/test-mdi.cpp
        ../../unittets/test-mpath.cc
        ../../unittets/test-mtra.cpp
        ../../unittets/test-mulp.cc
        ../../unittets/test-wheel-timer.cc
        ../../unittets/geco-test.cc
        ../../unittets/geco-test.h)
include_directories(../../thirdparty/googlemock/include ../../thirdparty/googletest/include ../../src)
link_directories(../geconetlib/cmake-build-debug ../../thirdparty/libs)
add_executable(gecounittest ${SOURCE_FILES})
target_link_libraries(gecounittest geconet_d gmock_ubuntu pthread)