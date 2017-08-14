# CMake Toolchain File to cross-compile rawrtc for arm using gcc

#target system is a linux
set (CMAKE_SYSTEM_NAME Linux)
#target processor is an arm with a version number <8
#this is relevant since the only problematic part of rawrtc is the intel-specific assembler code in crc32c.c and arm supports its own assembler instructions since version 8
set (CMAKE_SYSTEM_PROCESSOR arm)

#set the compilers
set (CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
set (CMAKE_CXX_COMPILER arm-linux-gnueabi-g++)

#Note: search path for libraries etc. is not changed, we are assuming that compilation is taking place in a docker container which handles those things
