cmake_minimum_required(VERSION 3.6)
project(untitled)

set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES library.cpp library.h)
add_library(untitled ${SOURCE_FILES})