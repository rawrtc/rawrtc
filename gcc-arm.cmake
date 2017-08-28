# CMake Toolchain File to cross-compile rawrtc for arm using gcc

#target system is a linux
set (CMAKE_SYSTEM_NAME Linux)
#target processor is an arm with a version number <8
#this is relevant since the only problematic part of rawrtc is the intel-specific assembler code in crc32c.c and arm supports its own assembler instructions since version 8
set (CMAKE_SYSTEM_PROCESSOR arm<8)

#set the compilers
set (CMAKE_C_COMPILER arm-linux-gnueabi-gcc)
set (CMAKE_CXX_COMPILER arm-linux-gnueabi-g++)

#Note: Alternate search paths for libraries, etc. are not set, it is assumed that cross-compilation will take place in a docker container
