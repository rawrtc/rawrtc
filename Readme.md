# RAWRTC

[![Build Status][travis-ci-badge]][travis-ci-url]

A WebRTC and ORTC library with a small footprint that runs everywhere.

## Features

The following list represents all features that are planned for RAWRTC.
Features with a check mark are already implemented.

* ICE [[draft-ietf-ice-rfc-5245bis-08]][ice]
  - [X] Trickle ICE [[draft-ietf-ice-trickle-07]][trickle-ice]
  - [X] IPv4
  - [X] IPv6
  - [X] UDP
  - [ ] TCP
* STUN [[RFC 5389]][stun]
  - [X] UDP
  - [ ] TCP
  - [ ] TLS over TCP
  - [ ] DTLS over UDP [[RFC 7350]][stun-turn-dtls]
* TURN [[RFC 5928]][turn]
  - [ ] UDP
  - [ ] TCP
  - [ ] TLS over TCP
  - [ ] DTLS over UDP [[RFC 7350]][stun-turn-dtls]
* Data Channel
  - [X] DCEP [[draft-ietf-rtcweb-data-protocol-09]][dcep]
  - [X] SCTP-based [[draft-ietf-rtcweb-data-channel-13]][sctp-dc]
* API
  - [ ] WebRTC C-API based on the [W3C WebRTC API][w3c-webrtc] and
    [[draft-ietf-rtcweb-jsep-19]][jsep]
  - [X] ORTC C-API based on the [W3C CG ORTC API][w3c-ortc]
* Other
  - [ ] SDP for WebRTC [[draft-ietf-rtcweb-sdp-03]][sdp]
  - [ ] IP Address Handling [[draft-ietf-rtcweb-ip-handling-03]][ip-handling]
  - [ ] DNS-based STUN/TURN server discovery

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
)> ./make-dependencies.sh
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

[travis-ci-badge]: https://travis-ci.org/rawrtc/rawrtc.svg?branch=master
[travis-ci-url]: https://travis-ci.org/rawrtc/rawrtc

[ice]: https://tools.ietf.org/html/draft-ietf-ice-rfc5245bis-08
[trickle-ice]: https://tools.ietf.org/html/draft-ietf-ice-trickle-07
[stun]: https://tools.ietf.org/html/rfc5389
[turn]: https://tools.ietf.org/html/rfc5928
[stun-turn-dtls]: https://tools.ietf.org/html/rfc7350
[dcep]: https://tools.ietf.org/html/draft-ietf-rtcweb-data-protocol-09
[sctp-dc]: https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13
[jsep]: https://tools.ietf.org/html/draft-ietf-rtcweb-jsep-19
[w3c-webrtc]: https://www.w3.org/TR/webrtc/
[w3c-ortc]: http://draft.ortc.org
[sdp]: https://tools.ietf.org/html/draft-ietf-rtcweb-sdp-03
[ip-handling]: https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-03
