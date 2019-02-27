#!/bin/sh
set -e

# Number of threads to use
export THREADS=12

# Library prefix
export LIB_PREFIX=rawrtc_

# Build path
if [ -z "$BUILD_PATH" ]; then
    export BUILD_PATH=${PWD}/build
fi

# Offline?
offline=false
if [ ! -z "$OFFLINE" ]; then
    offline=true
fi

# Dependencies
LIBREW_GIT="https://github.com/rawrtc/rew.git"
LIBREW_BRANCH="meson"
LIBREW_COMMIT="92e5e6190281fd1003ea629a2baa394e0673b2c0"
LIBREW_PATH="rew"
RAWRTCDC_GIT="https://github.com/rawrtc/rawrtc-data-channel.git"
RAWRTCDC_BRANCH="meson"
RAWRTCDC_PATH="rawrtcdc"

# Prefix
export PREFIX=${BUILD_PATH}/prefix
export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:${PREFIX}/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH}
echo "Environment vars:"
echo "PREFIX: ${PREFIX}"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH}"
echo ""

mkdir -p ${BUILD_PATH}/dependencies
MAIN_DIR=${BUILD_PATH}/dependencies
cd ${MAIN_DIR}

# Check for DTLS 1.2 suppport in openssl
echo "OpenSSL version: `pkg-config --short-errors --modversion openssl`"
pkg-config --atleast-version=1.0.2 openssl || (echo "No DTLS 1.2 support, exiting!" && exit 1)

# Get librew
if [ -z "$SKIP_LIBREW" ]; then
    if [ ! -d "${LIBREW_PATH}" ]; then
        echo "Cloning librew"
        git clone -b ${LIBREW_BRANCH} ${LIBREW_GIT} ${LIBREW_PATH}
        cd ${LIBREW_PATH}
    elif [ "$offline" = false ]; then
        cd ${LIBREW_PATH}
        echo "Pulling librew"
        git pull
    else
        cd ${LIBREW_PATH}
    fi
    git checkout ${LIBREW_BRANCH}
    git reset --hard ${LIBREW_COMMIT}
    cd ${MAIN_DIR}
fi

# Get RAWRTCDC
if [ -z "$SKIP_RAWRTCDC" ]; then
    if [ ! -d "${RAWRTCDC_PATH}" ]; then
        echo "Cloning RAWRTCDC"
        git clone -b ${RAWRTCDC_BRANCH} ${RAWRTCDC_GIT} ${RAWRTCDC_PATH}
        cd ${RAWRTCDC_PATH}
    elif [ "$offline" = false ]; then
        cd ${RAWRTCDC_PATH}
        echo "Pulling RAWRTCDC"
        git pull
    else
        cd ${RAWRTCDC_PATH}
    fi
    git checkout ${RAWRTCDC_BRANCH}
    cd ${MAIN_DIR}
fi

# Build librew
if [ -z "$SKIP_LIBREW" ]; then
    cd ${LIBREW_PATH}
    rm -rf build
    mkdir build
    echo "Configuring librew"
    meson build --prefix ${PREFIX} --default-library static
    echo "Building librew"
    cd build
    ninja install
    cd ${MAIN_DIR}
fi

# Build RAWRTCDC (and dependencies, implicitly builds RAWRTCC)
if [ -z "$SKIP_RAWRTCDC" ]; then
    cd ${RAWRTCDC_PATH}
    rm -rf build
    mkdir build
    echo "Configuring RAWRTCDC"
    meson build --prefix ${PREFIX} --default-library static
    echo "Building RAWRTCDC"
    cd build
    ninja install
    cd ${MAIN_DIR}
fi
