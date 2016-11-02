# Project
cmake_minimum_required(VERSION 3.2)
project(anyrtc)
set(anyrtc_VERSION_MAJOR 0)
set(anyrtc_VERSION_MINOR 0)
set(anyrtc_VERSION_PATCH 1)

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

# TODO: Dependency: zf_log
include_directories(/home/lenny/Projects/anyrtc/anyrtc/build.cmake/prefix/include)

# Dependency: OpenSSL (TODO: Move to libre)
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
# TODO: Use find_package as usrsctp has cmake support
find_library(LIB_USRSCTP_LIBRARIES NAMES usrsctp libusrsctp)

# Dependencies library list
set(anyrtc_DEP_LIBRARIES
        ${LIB_RE_LIBRARIES}
        ${LIB_REW_LIBRARIES}
        ${LIB_OPENSSL_LIBRARIES}
        ${LIB_USRSCTP_LIBRARIES})

# Walk through subdirectories
add_subdirectory(src)

# TODO: Generate pkg entry
