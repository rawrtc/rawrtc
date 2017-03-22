# Project
cmake_minimum_required(VERSION 3.2)
project(librawrtc
        VERSION 0.0.1)
set(PROJECT_DESCRIPTION
        "A WebRTC and ORTC library with a small footprint that runs everywhere.")
set(PROJECT_URL
        "https://github.com/rawrtc/rawrtc")

# Dependency versions
set(OPENSSL_VERSION "openssl >= 1.0.2")
set(LIB_RE_VERSION "libre >= 0.5.0")
set(LIB_REW_VERISON "librew >= 0.4.0")
# Note: This MUST be here as cmake 3.5.0 overwrites LIB_RE_VERSION for some reason...
set(DEPENDENCY_VERSIONS "${OPENSSL_VERSION}, ${LIB_RE_VERSION}, ${LIB_REW_VERISON}")

# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif ()

# Enable verbose output in DEBUG mode
if (${CMAKE_BUILD_TYPE} MATCHES "DEBUG")
    message(STATUS "enabling verbose outout")
    set(CMAKE_VERBOSE_MAKEFILE on)
endif ()

# Use pkg-config
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

# Dependency list
set(rawrtc_DEP_LIBRARIES)

# Dependency: Threads
list(APPEND rawrtc_DEP_LIBRARIES
        Threads::Threads)

# Apple-specific dependencies
# TODO: This should probably be in libre's pkg-config file in Libs.private
if (APPLE)
    find_library(LIB_SYSTEM_CONFIGURATION_LIBRARIES NAMES SystemConfiguration)
    find_library(LIB_CORE_FOUNDATION_LIBRARIES NAMES CoreFoundation)
    list(APPEND rawrtc_DEP_LIBRARIES
            ${LIB_SYSTEM_CONFIGURATION_LIBRARIES}
            ${LIB_CORE_FOUNDATION_LIBRARIES})
endif ()

# Dependency: OpenSSL
pkg_check_modules(LIB_OPENSSL REQUIRED ${OPENSSL_VERSION})
include_directories(${LIB_OPENSSL_INCLUDE_DIRS})
link_directories(${LIB_OPENSSL_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_OPENSSL_LIBRARIES})

# Dependency: libre
pkg_check_modules(LIB_RE REQUIRED ${LIB_RE_VERSION})
include_directories(${LIB_RE_INCLUDE_DIRS})
link_directories(${LIB_RE_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_RE_LIBRARIES})

# Dependency: librew
pkg_check_modules(LIB_REW REQUIRED ${LIB_REW_VERISON})
include_directories(${LIB_REW_INCLUDE_DIRS})
link_directories(${LIB_REW_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_REW_LIBRARIES})

# Dependency: usrsctp
# TODO: Use the pkg-config file of usrsctp once it has been added
find_library(LIB_USRSCTP_LIBRARIES NAMES usrsctp.a libusrsctp.a)
find_path(LIB_USRSCTP_INCLUDE_DIRS usrsctp.h)
get_filename_component(LIB_USRSCTP_LIBRARY_DIRS ${LIB_USRSCTP_LIBRARIES} DIRECTORY)
include_directories(${LIB_USRSCTP_INCLUDE_DIRS})
link_directories(${LIB_USRSCTP_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_USRSCTP_LIBRARIES})

# Dependency versions
set(PKG_CONFIG_REQUIRES "")
set(PKG_CONFIG_REQUIRES_PRIVATE "${DEPENDENCY_VERSIONS}")

# Linker flags (includes libs that have no pkg-config files)
set(PKG_CONFIG_LIB_DIRS "-L\${libdir}")
set(PKG_CONFIG_LIBRARIES "-lrawrtc")
set(PKG_CONFIG_LIBS "${PKG_CONFIG_LIB_DIRS} ${PKG_CONFIG_LIBRARIES}")
set(PKG_CONFIG_LIB_DIRS_PRIVATE "${PKG_CONFIG_LIB_DIRS} -L${LIB_USRSCTP_LIBRARY_DIRS}")
set(PKG_CONFIG_LIBRARIES_PRIVATE "${PKG_CONFIG_LIBRARIES} ${LIB_USRSCTP_LIBRARIES}")
set(PKG_CONFIG_LIBS_PRIVATE "${PKG_CONFIG_LIB_DIRS_PRIVATE} ${PKG_CONFIG_LIBRARIES_PRIVATE}")

# Cflags (includes includes that have no pkg-config files)
set(PKG_CONFIG_CFLAGS "-I\${includedir} -I${LIB_USRSCTP_INCLUDE_DIRS}")

# Add custom target to install the library
add_custom_target(install-${PROJECT_NAME}
        $(MAKE) install
        DEPENDS ${PROJECT_NAME}
        COMMENT "Installing ${PROJECT_NAME}")

# Walk through subdirectories
add_subdirectory(src)
