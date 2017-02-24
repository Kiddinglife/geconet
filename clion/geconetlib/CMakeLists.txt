cmake_minimum_required(VERSION 3.6)
project(geconetlib)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES
        ../../src/geco-bit-stream.cpp
        ../../src/geco-bit-stream.h
        ../../src/geco-common.h
        ../../src/geco-ds-config.h
        ../../src/geco-ds-malloc.h
        ../../src/geco-ds-timer.h
        ../../src/geco-malloc.cc
        ../../src/geco-malloc.h
        ../../src/geco-net-auth.cc
        ../../src/geco-net-auth.h
        ../../src/geco-net-chunk.cc
        ../../src/geco-net-chunk.h
        ../../src/geco-net-common.cc
        ../../src/geco-net-common.h
        ../../src/geco-net-config.h
        ../../src/geco-net-dispatch.cc
        ../../src/geco-net-dispatch.h
        ../../src/geco-net-msg.h
        ../../src/geco-net-timer.cc
        ../../src/geco-net-transport.cc
        ../../src/geco-net-transport.h
        ../../src/geco-net.h
        ../../src/geco-thread.h
        ../../src/spsc-queue.h
        ../../src/timestamp.cc
        ../../src/timestamp.h
        ../../src/wheel-timer-bitops.cc
        ../../src/wheel-timer-debug.h
        ../../src/wheel-timer-queue.h
        ../../src/wheel-timer.cc
        ../../src/wheel-timer.h)
add_library(geconet_d ${SOURCE_FILES})