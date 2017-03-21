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

# Dependencies
OPENSSL_VERSION="1.1.0e"
OPENSSL_URL="https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
OPENSSL_PATH="openssl"
LIBRE_GIT="https://github.com/rawrtc/re.git"
LIBRE_BRANCH="rawrtc-patched"
LIBRE_PATH="re"
LIBREW_GIT="https://github.com/rawrtc/rew.git"
LIBREW_BRANCH="gather_without_role"
LIBREW_PATH="rew"
USRSCTP_GIT="https://github.com/rawrtc/usrsctp.git"
USRSCTP_BRANCH="usrsctp-for-rawrtc"
USRSCTP_PATH="usrsctp"

# Prefix
export PREFIX=${BUILD_PATH}/prefix
export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}
export CFLAGS="${CFLAGS} -I${PREFIX}/include"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS} -L${PREFIX}/lib"
echo "Environment vars:"
echo "PREFIX: ${PREFIX}"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH}"
echo "CFLAGS: ${CFLAGS}"
echo "CPPFLAGS: ${CPPFLAGS}"
echo "LDFLAGS: ${LDFLAGS}"
echo ""

mkdir -p ${BUILD_PATH}/dependencies
MAIN_DIR=${BUILD_PATH}/dependencies
cd ${MAIN_DIR}

# Extra cflags when using clang
clang_extra_cflags=""
if [ "${CC}" = "clang" ]; then
    clang_extra_cflags=" -Wno-error=unused-command-line-argument"
fi

# Check for DTLS 1.2 suppport in openssl
echo "OpenSSL version: `pkg-config --short-errors --modversion openssl`"
have_dtls_1_2=true
pkg-config --atleast-version=1.0.2 openssl || have_dtls_1_2=false
echo "OpenSSL DTLS 1.2 support: $have_dtls_1_2"

# Check if we need to fetch & install openssl
need_openssl=false
if ([ ! -z "$ENFORCE_OPENSSL" ] && [ "${ENFORCE_OPENSSL}" = "1" ]) || [ "$have_dtls_1_2" = false ]; then
    # Already installed? Check version
    if [ -d "${OPENSSL_PATH}" ]; then
        # Outdated?
        pkg-config --atleast-version=${OPENSSL_VERSION} openssl || need_openssl=true
    else
        # Not downloaded
        need_openssl=true
    fi
fi
echo "Need to fetch OpenSSL: $need_openssl"

# Get openssl
if [ "$need_openssl" = true ]; then
    rm -rf ${OPENSSL_PATH}
    echo "Fetching OpenSSL"
    wget ${OPENSSL_URL}
    tar -xzf openssl-${OPENSSL_VERSION}.tar.gz
    mv openssl-${OPENSSL_VERSION} ${OPENSSL_PATH}
fi

# Get usrsctp
if [ ! -d "${USRSCTP_PATH}" ]; then
    echo "Cloning usrsctp"
    git clone --depth=1 -b ${USRSCTP_BRANCH} ${USRSCTP_GIT} ${USRSCTP_PATH}
else
    cd ${USRSCTP_PATH}
    echo "Pulling usrsctp"
    git pull
    cd ${MAIN_DIR}
fi

# Get libre
if [ ! -d "${LIBRE_PATH}" ]; then
    echo "Cloning libre"
    git clone --depth=1 -b ${LIBRE_BRANCH} ${LIBRE_GIT} ${LIBRE_PATH}
    cd ${LIBRE_PATH}
    echo "Patching libre"
    patch << "EOF"
--- Makefile
+++ Makefile
@@ -34,11 +34,13 @@
 MODULES += json
 
 INSTALL := install
+ifndef PREFIX
 ifeq ($(DESTDIR),)
 PREFIX  := /usr/local
 else
 PREFIX  := /usr
 endif
+endif
 ifeq ($(LIBDIR),)
 LIBDIR  := $(PREFIX)/lib
 endif
@@ -84,7 +86,10 @@
 	@echo 'Description: ' >> libre.pc
 	@echo 'Version: '$(VERSION) >> libre.pc
 	@echo 'URL: http://creytiv.com/re.html' >> libre.pc
-	@echo 'Libs: -L$${libdir} -lre' >> libre.pc
+	# TODO: Change this back as soon as meson does call pkg-config with --static
+	#@echo 'Libs: -L$${libdir} -lre' >> libre.pc
+	@echo 'Libs: -L$${libdir} -lre ${LIBS}' >> libre.pc
+	@echo 'Libs.private: ${LIBS}' >> libre.pc
 	@echo 'Cflags: -I$${includedir}' >> libre.pc
 
 $(BUILD)/%.o: src/%.c $(BUILD) Makefile $(MK) $(MODMKS)
EOF
    patch -p0 << "EOF"
--- mk/re.mk
+++ mk/re.mk
@@ -427,8 +427,11 @@
 # External libraries section
 #
 
-USE_OPENSSL := $(shell [ -f $(SYSROOT)/include/openssl/ssl.h ] || \
-	[ -f $(SYSROOT)/local/include/openssl/ssl.h ] || \
+ifeq ($(OPENSSL_SYSROOT),)
+OPENSSL_SYSROOT := $(SYSROOT)
+endif
+USE_OPENSSL := $(shell [ -f $(OPENSSL_SYSROOT)/include/openssl/ssl.h ] || \
+	[ -f $(OPENSSL_SYSROOT)/local/include/openssl/ssl.h ] || \
 	[ -f $(SYSROOT_ALT)/include/openssl/ssl.h ] && echo "yes")
 
 ifneq ($(USE_OPENSSL),)
@@ -436,12 +439,12 @@
 LIBS    += -lssl -lcrypto
 USE_TLS := yes
 
-USE_OPENSSL_DTLS := $(shell [ -f $(SYSROOT)/include/openssl/dtls1.h ] || \
-	[ -f $(SYSROOT)/local/include/openssl/dtls1.h ] || \
+USE_OPENSSL_DTLS := $(shell [ -f $(OPENSSL_SYSROOT)/include/openssl/dtls1.h ] || \
+	[ -f $(OPENSSL_SYSROOT)/local/include/openssl/dtls1.h ] || \
 	[ -f $(SYSROOT_ALT)/include/openssl/dtls1.h ] && echo "yes")
 
-USE_OPENSSL_SRTP := $(shell [ -f $(SYSROOT)/include/openssl/srtp.h ] || \
-	[ -f $(SYSROOT)/local/include/openssl/srtp.h ] || \
+USE_OPENSSL_SRTP := $(shell [ -f $(OPENSSL_SYSROOT)/include/openssl/srtp.h ] || \
+	[ -f $(OPENSSL_SYSROOT)/local/include/openssl/srtp.h ] || \
 	[ -f $(SYSROOT_ALT)/include/openssl/srtp.h ] && echo "yes")
 
 ifneq ($(USE_OPENSSL_DTLS),)
EOF
    cd ${MAIN_DIR}
else
    cd ${LIBRE_PATH}
    echo "Pulling libre"
    git pull
    cd ${MAIN_DIR}
fi

# Get librew
if [ ! -d "${LIBREW_PATH}" ]; then
    echo "Cloning librew"
    git clone --depth=1 -b ${LIBREW_BRANCH} ${LIBREW_GIT} ${LIBREW_PATH}
    cd ${LIBREW_PATH}
    echo "Patching librew"
    patch << "EOF"
--- Makefile
+++ Makefile
@@ -33,11 +33,13 @@
 LIBS    += -lm
 
 INSTALL := install
+ifndef PREFIX
 ifeq ($(DESTDIR),)
 PREFIX  := /usr/local
 else
 PREFIX  := /usr
 endif
+endif
 ifeq ($(LIBDIR),)
 LIBDIR  := $(PREFIX)/lib
 endif
@@ -75,6 +77,22 @@
 	@$(RANLIB) $@
 endif
 
+librew.pc:
+	@echo 'prefix='$(PREFIX) > librew.pc
+	@echo 'exec_prefix=$${prefix}' >> librew.pc
+	@echo 'libdir=$${prefix}/lib' >> librew.pc
+	@echo 'includedir=$${prefix}/include/rew' >> librew.pc
+	@echo '' >> librew.pc
+	@echo 'Name: librew' >> librew.pc
+	@echo 'Description: ' >> librew.pc
+	@echo 'Version: '$(VERSION) >> librew.pc
+	@echo 'URL: https://github.com/alfredh/rew' >> librew.pc
+	# TODO: Change this back as soon as meson does call pkg-config with --static
+	#@echo 'Libs: -L$${libdir} -lrew' >> librew.pc
+	@echo 'Libs: -L$${libdir} -lrew ${LIBS}' >> librew.pc
+	@echo 'Libs.private: ${LIBS}' >> librew.pc
+	@echo 'Cflags: -I$${includedir}' >> librew.pc
+
 $(BUILD)/%.o: src/%.c $(BUILD) Makefile $(MK) $(MODMKS)
 	@echo "  CC      $@"
 	@$(CC) $(CFLAGS) -c $< -o $@ $(DFLAGS)
@@ -92,27 +110,30 @@
 
 .PHONY: clean
 clean:
-	@rm -rf $(SHARED) $(STATIC) test.d test.o test $(BUILD)
+	@rm -rf $(SHARED) $(STATIC) librew.pc test.d test.o test $(BUILD)
 
 
-install: $(SHARED) $(STATIC)
+install: $(SHARED) $(STATIC) librew.pc
 	@mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR)
 	$(INSTALL) -m 0644 $(shell find include -name "*.h") \
 		$(DESTDIR)$(INCDIR)
 	$(INSTALL) -m 0755 $(SHARED) $(DESTDIR)$(LIBDIR)
 	$(INSTALL) -m 0755 $(STATIC) $(DESTDIR)$(LIBDIR)
+	$(INSTALL) -m 0644 librew.pc $(DESTDIR)$(LIBDIR)/pkgconfig
 
-install-static: $(STATIC)
+install-static: $(STATIC) librew.pc
 	@mkdir -p $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCDIR)
 	$(INSTALL) -m 0644 $(shell find include -name "*.h") \
 		$(DESTDIR)$(INCDIR)
 	$(INSTALL) -m 0755 $(STATIC) $(DESTDIR)$(LIBDIR)
+	$(INSTALL) -m 0644 librew.pc $(DESTDIR)$(LIBDIR)/pkgconfig
 
 .PHONY: uninstall
 uninstall:
 	@rm -rf $(DESTDIR)$(INCDIR)
 	@rm -f $(DESTDIR)$(LIBDIR)/$(SHARED)
 	@rm -f $(DESTDIR)$(LIBDIR)/$(STATIC)
+	@rm -f $(DESTDIR)$(LIBDIR)/pkgconfig/librew.pc
 
 -include test.d
EOF
    cd ${MAIN_DIR}
else
    cd ${LIBREW_PATH}
    echo "Pulling librew"
    git pull
    cd ${MAIN_DIR}
fi

# Build openssl
if [ "$need_openssl" = true ]; then
    cd ${OPENSSL_PATH}
    echo "Configuring OpenSSL"
    ./config shared --prefix=${PREFIX}
    echo "Building OpenSSL"
    make
    echo "Installing OpenSSL"
    make install
    cd ${MAIN_DIR}
fi

# Set openssl sysroot
openssl_sysroot=`pkg-config --variable=prefix openssl`
echo "Using OpenSSL sysroot: $openssl_sysroot"

# Build usrsctp
cd ${USRSCTP_PATH}
if [ ! -d "build" ]; then
    mkdir build
fi
cd build
echo "Configuring usrsctp"
CFLAGS=-fPIC \
cmake -DCMAKE_INSTALL_PREFIX=${PREFIX} -DSCTP_DEBUG=1 ..
echo "Cleaning usrsctp"
make clean
echo "Building & installing usrsctp"
# TODO: Treat warnings as errors
make install -j${THREADS}
rm -f ${PREFIX}/lib/libusrsctp.so* ${PREFIX}/lib/libusrsctp.*dylib
cd ${MAIN_DIR}

# Build libre
cd ${LIBRE_PATH}
echo "Cleaning libre"
make clean
echo "Building libre"
if [ "$have_dtls_1_2" = false ]; then
    OPENSSL_SYSROOT=$openssl_sysroot \
    EXTRA_CFLAGS="-Werror${clang_extra_cflags}" \
    make install
else
    make install
fi
rm -f ${PREFIX}/lib/libre.so ${PREFIX}/lib/libre.*dylib
cd ${MAIN_DIR}

# Build librew
cd ${LIBREW_PATH}
echo "Cleaning librew"
make clean
echo "Building librew"
LIBRE_INC=${MAIN_DIR}/${LIBRE_PATH}/include \
EXTRA_CFLAGS="-Werror${clang_extra_cflags}" \
make install-static
cd ${MAIN_DIR}
