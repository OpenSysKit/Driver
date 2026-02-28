cmake_minimum_required(VERSION 3.16)
project(OpenSysKitDriver C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(OpenSysKit
    src/driver.cpp
    src/process.cpp
    src/callbacks.cpp
)

target_include_directories(OpenSysKit PRIVATE src)
target_compile_options(OpenSysKit PRIVATE /utf-8)
