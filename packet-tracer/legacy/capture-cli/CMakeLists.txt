cmake_minimum_required(VERSION 3.20)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" PKTANA_TRACER_VERSION)
string(STRIP "${PKTANA_TRACER_VERSION}" PKTANA_TRACER_VERSION)

project(pktana-packet-tracer
    VERSION ${PKTANA_TRACER_VERSION}
    DESCRIPTION "Cross-platform packet tracer for macOS and Windows"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(PKTANA_TRACER_BUILD_TESTS "Build unit tests" OFF)

include(GNUInstallDirs)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/pktana/tracer/version.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/pktana/tracer/version.hpp"
    @ONLY
)

find_package(Threads REQUIRED)
find_package(PCAP REQUIRED)

add_executable(pktana-tracer
    src/main.cpp
    src/capture.cpp
    src/util.cpp
)

target_include_directories(pktana-tracer
    PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        "${CMAKE_CURRENT_BINARY_DIR}/generated"
)

target_link_libraries(pktana-tracer
    PRIVATE
        Threads::Threads
        PCAP::PCAP
)

if(MSVC)
    target_compile_options(pktana-tracer PRIVATE /W4 /permissive-)
else()
    target_compile_options(pktana-tracer PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    target_compile_definitions(pktana-tracer PRIVATE PKTANA_TRACER_PLATFORM_WINDOWS=1)
    target_link_libraries(pktana-tracer PRIVATE ws2_32 iphlpapi)
elseif(APPLE)
    target_compile_definitions(pktana-tracer PRIVATE PKTANA_TRACER_PLATFORM_MACOS=1)
endif()

install(TARGETS pktana-tracer RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
