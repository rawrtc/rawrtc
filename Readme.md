# rawrtc

A WebRTC and ORTC library with a small footprint that runs everywhere.

## Prerequisites

The following packages are required:

* [git](https://git-scm.com)
* [cmake](https://cmake.org) >= 3.2
* pkg-config
* SSL development libraries (libssl-dev)

### Meson (Alternative Build System)

~~If you want to use Meson instead of CMake, you have to install both the Meson
build system and Ninja.~~ Use CMake for now. Meson will be updated later.

* [meson](https://github.com/mesonbuild/meson)
* [ninja](https://ninja-build.org)

## Build

The following instruction will use a custom *prefix* to avoid installing
the necessary dependencies and this library system-wide.

### Dependencies & Meson Configuration

```
> cd <path-to-rawrtc>
> ./make-dependencies.sh
```

### Package Configuration Path

The following environment variable is required for both Meson and CMake to find
the previously built dependencies:

```
> export PKG_CONFIG_PATH=${PWD}/build/prefix/lib/pkgconfig:${PWD}/build/prefix/lib/x86_64-linux-gnu/pkgconfig
```

Note that this command will need to be repeated once the terminal has been
closed.

### Compile

#### Meson

```
> cd <path-to-rawrtc>
> meson build --default-library=static --prefix=${PWD}/build/prefix
> cd build
> ninja install
```

#### CMake

```
> cd <path-to-rawrtc>/build
> cmake -DCMAKE_INSTALL_PREFIX=${PWD}/prefix ..
> make install
```

## Run

Because we have used a custom *prefix*, we need to add the prefix to the
path to run the various binaries. To be able to find the shared library
when running a binary, the library path has to be set as well.
Note: We assume that you are in the `build` directory.

```
> export LD_LIBRARY_PATH=${PWD}/prefix/lib:${LD_LIBRARY_PATH}
> export PATH=${PWD}/prefix/bin:${PATH}
```

## data-channel-sctp

```
> data-channel-sctp <0|1 (ice-role)> [<sctp-port>]
```
