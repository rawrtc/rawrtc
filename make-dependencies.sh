#!/bin/sh
set -e

# Number of threads to use
export THREADS=12

# Library prefix
export LIB_PREFIX=anyrtc_

# Build path
export BUILD_PATH=${PWD}/build

# Dependencies
OPENSSL_URL="https://www.openssl.org/source/openssl-1.0.2g.tar.gz"
OPENSSL_TAR="openssl-1.0.2g.tar.gz"
OPENSSL_PATH="openssl-1.0.2g"
ZF_LOG_GIT="https://github.com/wonder-mice/zf_log.git"
ZF_LOG_PATH="zf_log"
ZF_LOG_BUILD_PATH="zf_log.build"
LIBRE_GIT="vcs@vcs.zwuenf.org:anyrtc/re.git"
LIBRE_PATH="re"
LIBREW_GIT="https://github.com/alfredh/rew.git"
LIBREW_PATH="rew"

# Prefix
export PREFIX=${BUILD_PATH}/prefix
export PKG_CONFIG_PATH=${PREFIX}/lib/pkgconfig

export CFLAGS="${CFLAGS} -I${PREFIX}/include"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${LDFLAGS} -L${PREFIX}/lib"

mkdir -p ${BUILD_PATH}/dependencies
MAIN_DIR=${BUILD_PATH}/dependencies
cd ${MAIN_DIR}

# Check for DTLS 1.2 suppport in openssl
openssl_version=`openssl version`
case "$openssl_version" in
    *"1.0.2"*) have_dtls_1_2=true ;;
    *) have_dtls_1_2=false ;;
esac

# Get openssl
if [ ! -d "${OPENSSL_PATH}" ]; then
    wget ${OPENSSL_URL}
    tar -xzf ${OPENSSL_TAR}
fi

# Get zf_log
if [ ! -d "${ZF_LOG_PATH}" ] && [ "$have_dtls_1_2" = false ]; then
    git clone --depth=1 ${ZF_LOG_GIT}
else
    cd ${ZF_LOG_PATH}
    git pull
    cd ${MAIN_DIR}
fi

# Get libre
if [ ! -d "${LIBRE_PATH}" ]; then
    git clone ${LIBRE_GIT} ${LIBRE_PATH}
    cd ${LIBRE_PATH}
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
    git pull
    cd ${MAIN_DIR}
fi

# Get librew
if [ ! -d "${LIBREW_PATH}" ]; then
    git clone --depth=1 ${LIBREW_GIT}
    cd ${LIBREW_PATH}
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
    git pull
    cd ${MAIN_DIR}
fi

# Build openssl
if [ "$have_dtls_1_2" = false ] && [ -z "$SKIP_OPENSSL" ]; then
cd ${OPENSSL_PATH}
./config --prefix=${PREFIX}
make
make install
cd ${MAIN_DIR}
fi

# Build zf_log
if [ ! -d "${ZF_LOG_BUILD_PATH}" ]; then
    mkdir zf_log.build
fi
cd ${ZF_LOG_BUILD_PATH}
CFLAGS=-fPIC cmake ../${ZF_LOG_PATH} -DCMAKE_INSTALL_PREFIX=${PREFIX} -DZF_LOG_LIBRARY_PREFIX=${LIB_PREFIX}
make install -j${THREADS}
cd ${MAIN_DIR}

# Build libre
cd ${LIBRE_PATH}
if [ "$have_dtls_1_2" = false ]; then
OPENSSL_SYSROOT=${PREFIX} make install -j${THREADS}
else
make install -j${THREADS}
fi
rm ${PREFIX}/lib/libre.so
cd ${MAIN_DIR}

# Build librew
cd ${LIBREW_PATH}
LIBRE_INC=${MAIN_DIR}/${LIBRE_PATH}/include make install-static -j${THREADS}
cd ${MAIN_DIR}
