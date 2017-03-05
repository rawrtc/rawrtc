# starting from a base image of Ubuntu
FROM ubuntu:latest

# **** Base System Initialization and Setup  ****

# Install the required libraries:
# - Gcc for compiler
# - Git for source code access
# - Cmake for build configuration
# - Pkg_config to aide CMake in package sourcing see: https://autotools.io/pkgconfig/pkg_check_modules.html
# - libssl for access to build requirements for encryption protocols
RUN apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install -y gcc git cmake pkg-config libssl-dev 

# Lets set the working directory to root
WORKDIR /

# **** Source Setup : Grab the latest master branch, clone locally  ****
RUN git clone https://github.com/rawrtc/rawrtc

# Now change directory : you are now in /rawrtc/ and subsequent commands will execute from this path
WORKDIR /rawrtc

# **** Environment variables : Set the environment variables for RAWRTC ****
# Set the path for Package config to find the libraries required to build RAWRTC
ENV PKG_CONFIG_PATH /rawrtc/build/prefix/lib/pkgconfig:/rawrtc/build/prefix/lib/x86_64-linux-gnu/pkgconfig

# Amend the lib directory to the current LD_LIBRARY_PATH so our binaries can dynamically load the required functions
# See https://linux.die.net/man/8/ld-linux 
ENV LD_LIBRARY_PATH /rawrtc/build/prefix/lib:${LD_LIBRARY_PATH}

# Lets add our (soon to be) built binaries into the path so we can run them from anywhere.
ENV PATH /rawrtc/build/prefix/bin:${PATH}

# **** Build RAWRTC : we are currently in /rawrtc ****
# We will begin by grabbing all the RAWRTC dependancies: Namely
# - Version specific OpenSSL (need dtls support)
# - A Userspace SCTP baseline (see https://github.com/NEAT-project/usrsctp-neat)
# - Version specific Libre (see http://www.creytiv.com/) for ICE, TURN, DNS etc and their dependancies
# Then we change directories into the build path
# Then we execute the cmake command to generate the build plan and ensure we pass all prebuild checks
# Finally we make and install RAWRTC
RUN	./make-dependencies.sh \
	&& cd build \
	&& cmake -DCMAKE_INSTALL_PREFIX=${PWD}/prefix .. \
	&& make install \
