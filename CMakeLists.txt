cmake_minimum_required(VERSION 3.16)
project(OpenSysKitDriver C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
find_package(WDK REQUIRED)

wdk_add_driver(OpenSysKit
    src/driver.cpp
    src/dkom.cpp
    src/freeze.cpp
    src/handle.cpp
    src/inject.cpp
    src/kernelmod.cpp
    src/memory.cpp
    src/network.cpp
    src/process.cpp
    src/protect.cpp
    src/threads.cpp
    src/token.cpp
    src/unload_driver.cpp
)

target_include_directories(OpenSysKit PRIVATE src)
target_compile_options(OpenSysKit PRIVATE /utf-8 /GS-)
target_compile_options(OpenSysKit PRIVATE /Oi)

if(CMAKE_GENERATOR_PLATFORM STREQUAL "ARM64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
    target_compile_definitions(OpenSysKit PRIVATE 
        _ARM64_
        _USE_INTRINSIC_INTERLOCKED_EXCHANGE_POINTER
    )
endif()

target_link_options(OpenSysKit PRIVATE /INTEGRITYCHECK)