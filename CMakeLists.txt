# Project
cmake_minimum_required(VERSION 3.2)
# TODO: Find a way to keep this in sync with the one in rawrtc.h
project(librawrtc
        VERSION 0.2.1)
set(PROJECT_DESCRIPTION
        "A WebRTC and ORTC library with a small footprint that runs everywhere.")
set(PROJECT_URL
        "https://github.com/rawrtc/rawrtc")

# Use prefix pkgconfig
set(ENV{PKG_CONFIG_PATH} "${CMAKE_INSTALL_PREFIX}/lib/pkgconfig/:$ENV{PKG_CONFIG_PATH}")

# Dependency versions
set(LIB_RE_VERSION "libre >= 0.5.7")
set(LIB_REW_VERSION "librew >= 0.5.0")
set(LIB_RAWRTCC_VERSION "librawrtcc >= 0.0.1")
set(LIB_RAWRTCDC_VERSION "librawrtcdc >= 0.0.1")
# Note: This MUST be here as cmake 3.5.0 overwrites LIB_RE_VERSION for some reason...
set(DEPENDENCY_VERSIONS "${LIB_RE_VERSION}, ${LIB_REW_VERSION}, ${LIB_RAWRTCC_VERSION}, ${LIB_RAWRTCDC_VERSION}")

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

# Flag for enabling building of SCTP redirect transport
set(SCTP_REDIRECT_TRANSPORT OFF CACHE BOOL "Build the SCTP redirect transport tool.")

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

# Dependency: libre
pkg_check_modules(LIB_RE REQUIRED ${LIB_RE_VERSION})
include_directories(${LIB_RE_STATIC_INCLUDE_DIRS} ${LIB_RE_STATIC_INCLUDEDIR})
link_directories(${LIB_RE_STATIC_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_RE_STATIC_LIBRARIES})

# Dependency: librew
pkg_check_modules(LIB_REW REQUIRED ${LIB_REW_VERSION})
include_directories(${LIB_REW_STATIC_INCLUDE_DIRS} ${LIB_REW_STATIC_INCLUDEDIR})
link_directories(${LIB_REW_STATIC_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_REW_STATIC_LIBRARIES})

# Dependency: librawrtcc
pkg_check_modules(LIB_RAWRTCC REQUIRED ${LIB_RAWRTCC_VERSION})
include_directories(${LIB_RAWRTCC_STATIC_INCLUDE_DIRS} ${LIB_RAWRTCC_INCLUDEDIR})
link_directories(${LIB_RAWRTCC_STATIC_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_RAWRTCC_STATIC_LIBRARIES})

# Dependency: librawrtcdc
pkg_check_modules(LIB_RAWRTCDC REQUIRED ${LIB_RAWRTCDC_VERSION})
include_directories(${LIB_RAWRTCDC_STATIC_INCLUDE_DIRS} ${LIB_RAWRTCDC_INCLUDEDIR})
link_directories(${LIB_RAWRTCDC_STATIC_LIBRARY_DIRS})
list(APPEND rawrtc_DEP_LIBRARIES ${LIB_RAWRTCDC_STATIC_LIBRARIES})

# Dependency versions
set(PKG_CONFIG_REQUIRES "")
set(PKG_CONFIG_REQUIRES_PRIVATE "${DEPENDENCY_VERSIONS}")

# Linker flags (includes libs that have no pkg-config files)
set(PKG_CONFIG_LIB_DIRS "-L\${libdir}")
set(PKG_CONFIG_LIBRARIES "-lrawrtc")
set(PKG_CONFIG_LIBS "${PKG_CONFIG_LIB_DIRS} ${PKG_CONFIG_LIBRARIES}")
set(PKG_CONFIG_LIB_DIRS_PRIVATE "${PKG_CONFIG_LIB_DIRS}")
set(PKG_CONFIG_LIBRARIES_PRIVATE "${PKG_CONFIG_LIBRARIES}")
set(PKG_CONFIG_LIBS_PRIVATE "${PKG_CONFIG_LIB_DIRS_PRIVATE} ${PKG_CONFIG_LIBRARIES_PRIVATE}")

# Add custom target to install the library
add_custom_target(install-${PROJECT_NAME}
        $(MAKE) install
        COMMENT "Installing ${PROJECT_NAME}")

# Walk through subdirectories
add_subdirectory(src)
