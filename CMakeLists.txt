# Project
cmake_minimum_required(VERSION 3.2)
project(rawrtc)
set(rawrtc_VERSION_MAJOR 0)
set(rawrtc_VERSION_MINOR 0)
set(rawrtc_VERSION_PATCH 1)

# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif()

# Enable verbose output in DEBUG mode
if (${CMAKE_BUILD_TYPE} MATCHES "DEBUG")
    message(STATUS "enabling verbose outout")
    set(CMAKE_VERBOSE_MAKEFILE on)
endif()

# Use pkg-config
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# TODO: Dependency: zf_log
#include_directories(.../build.cmake/prefix/include)

# Dependency: OpenSSL
pkg_check_modules(LIB_OPENSSL REQUIRED openssl>=1.0.2)
include_directories(${LIB_OPENSSL_INCLUDE_DIRS})
link_directories(${LIB_OPENSSL_LIBRARY_DIRS})

# Dependency: libre
pkg_check_modules(LIB_RE REQUIRED libre>=0.4.15)
include_directories(${LIB_RE_INCLUDE_DIRS})
link_directories(${LIB_RE_LIBRARY_DIRS})

# Dependency: librew
pkg_check_modules(LIB_REW REQUIRED librew>=0.4.0)
include_directories(${LIB_REW_INCLUDE_DIRS})
link_directories(${LIB_REW_LIBRARY_DIRS})

# Dependency: usrsctp
# TODO: Add a pkg-config file to usrsctp
find_library(LIB_USRSCTP_LIBRARIES NAMES usrsctp libusrsctp)
find_path(LIB_USRSCTP_INCLUDE_DIRS usrsctp.h)
get_filename_component(LIB_USRSCTP_LIBRARY_DIRS ${LIB_USRSCTP_LIBRARIES} DIRECTORY)
include_directories(${LIB_USRSCTP_INCLUDE_DIRS})
link_directories(${LIB_USRSCTP_LIBRARY_DIRS})

# Dependencies library list
set(rawrtc_DEP_LIBRARIES
        Threads::Threads
        ${LIB_RE_LIBRARIES}
        ${LIB_REW_LIBRARIES}
        ${LIB_OPENSSL_LIBRARIES}
        ${LIB_USRSCTP_LIBRARIES})

# Walk through subdirectories
add_subdirectory(src)

# TODO: Generate pkg entry
