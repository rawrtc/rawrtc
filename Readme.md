# anyrtc

A WebRTC and ORTC library with a small footprint that runs everywhere.

## Prerequisites

* [meson](https://github.com/mesonbuild/meson)
* [ninja](https://ninja-build.org)
* [cmake](https://cmake.org) >= 3.2 (*zf_log* dependency)

## Build

The following instruction will use a custom *prefix* to avoid installing
the necessary dependencies and this library system-wide.

### Dependencies & Meson Configuration

```
> cd <path-to-anyrtc>
> ./make-dependencies.sh
> export PKG_CONFIG_PATH=${PWD}/build/prefix/lib/pkgconfig:${PWD}/build/prefix/lib/x86_64-linux-gnu/pkgconfig
> meson build --default-library=static --prefix=${PWD}/build/prefix
```

### Compile

```
> cd build
> export PKG_CONFIG_PATH=${PWD}/prefix/lib/pkgconfig:${PWD}/build/prefix/lib/x86_64-linux-gnu/pkgconfig
> ninja install
```

## Run

Because we have used a custom *prefix*, we need to add the prefix to the
path to run the various binaries.  
Note: We assume that you are in the `build` directory.

```
> export PATH=${PWD}/prefix/bin:${PATH}
```

### redirect-sctp

```
> redirect-sctp <0|1 (offerer)> <redirect-ip>
```
