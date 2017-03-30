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
  - [ ] SDP for WebRTC [[draft-ietf-rtcweb-sdp-04]][sdp]
  - [ ] IP Address Handling [[draft-ietf-rtcweb-ip-handling-03]][ip-handling]
  - [ ] DNS-based STUN/TURN server discovery

## Prerequisites

The following packages are required:

* [git][git]
* [cmake][cmake] >= 3.2
* pkg-config (`pkgconf` for newer FreeBSD versions)
* SSL development libraries (`libssl-dev` on Debian, `openssl` on OSX and FreeBSD)
* GNU make (`gmake` on FreeBSD for `re` and `rew` dependencies)

### Meson (Alternative Build System)

~~If you want to use Meson instead of CMake, you have to install both the Meson
build system and Ninja.~~ Use CMake for now. Meson will be updated later.

* [meson][meson]
* [ninja][ninja]

## Build

The following instruction will use a custom *prefix* to avoid installing
the necessary dependencies and this library system-wide.

### Dependencies

    cd <path-to-rawrtc>
    ./make-dependencies.sh

### Package Configuration Path

The following environment variable is required for both Meson and CMake to find
the previously built dependencies:

    export PKG_CONFIG_PATH=${PWD}/build/prefix/lib/pkgconfig

Note that this command will need to be repeated once the terminal has been
closed.

### Compile

#### Meson

    cd <path-to-rawrtc>
    meson build --default-library=static --prefix=${PWD}/build/prefix
    cd build
    ninja install

#### CMake

    cd <path-to-rawrtc>/build
    cmake -DCMAKE_INSTALL_PREFIX=${PWD}/prefix ..
    make install

## Run

RAWRTC provides a lot of tools that can be used for quick testing purposes and
to get started. Let's go through them one by one. If you just want to check out
data channels and browser interoperation, skip to the
[`data-channel-sctp` tool chapter](#data-channel-sctp).

Because we have used a custom *prefix*, we need to add the prefix to the
path to run the various binaries. To be able to find the shared library
when running a binary, the library path has to be set as well.
Note: We assume that you are in the `build` directory.

    export LD_LIBRARY_PATH=${PWD}/prefix/lib:${LD_LIBRARY_PATH}
    export PATH=${PWD}/prefix/bin:${PATH}

Most of the tools have required or optional arguments which are shared among
tools. Below is a description for the various arguments:

#### ice-role

Determines the ICE role to be used by the ICE transport, where `0` means
*controlled* and `1` means *controlling*.

#### redirect-ip

The IP address on which an SCTP stack is listening.

Used in conjunction with `redirect-port`. Only used by the SCTP redirect
transport.

#### redirect-port

The port number on which an SCTP stack is listening.

Used in conjunction with `redirect-ip`. Only used by the SCTP redirect
transport.

#### sctp-port

The port number the internal SCTP stack is supposed to use. Defaults to `5000`.

Note: It doesn't matter which port you choose unless you want to be able to
debug SCTP messages. In this case, it's easier to distinguish the peers by
their port numbers.

#### maximum-message-size

The maximum message size of an SCTP message the external SCTP stack is able to
handle. `0` indicates that messages of arbitrary size can be handled. Defaults
to `0`.

Only used by the SCTP redirect transport.

#### ice-candidate-type

If supplied, one or more specific ICE candidate types will be enabled and all
other ICE candidate types will be disabled. Can be one of the following
strings:

* *host*
* *srflx*
* *prflx*
* *relay*

Note that this has no effect on the gathering policy. The candidates will be
gathered but they will simply be ignored by the tool.

If not supplied, all ICE candidate types are enabled.

### ice-gatherer

The ICE gatherer tool gathers and prints ICE candidates. Once gathering is
complete, the tool exits.

Usage:

    ice-gatherer

### ice-transport-loopback

The ICE transport loopback tool starts two ICE transport instances which
establish an ICE connection. Once you see the following line for both clients
*A* and *B*, the ICE connection has been established:

    (<client>) ICE transport state: connected

Usage:

    ice-transport-loopback [<ice-candidate-type> ...]

### dtls-transport-loopback

The DTLS transport loopback tool starts two DTLS transport instances which
work on top of an established ICE transport connection. As soon as the DTLS
connection has been established, it uses an internal interface to send raw data
on the DTLS transport to the other peer. There's currently no way to verify
that the data has been received but you can trace the packets using Wireshark.

To verify that the DTLS connection establishes, wait for the following line for
both clients *A* and *B*:

    (<client>) DTLS transport state change: connected

Usage:

    dtls-transport-loopback [<ice-candidate-type> ...]

### sctp-transport-loopback

The SCTP transport loopback tool starts two SCTP transport instances which
work on top of an established DTLS transport connection. As soon as the SCTP
connection has been established, it uses an internal interface to send raw data
on the SCTP transport to the other peer.

To verify that the SCTP connection establishes, wait for the following line for
both clients *A* and *B*:

    (<client>) SCTP transport state change: connected
    
The tool will output a warning (four times) in case the data has been
transmitted successfully:

    Ignored incoming DCEP control message with unknown type: 72

This warning is entirely valid as this tool sends invalid DCEP messages for
testing purposes.

Usage:

    sctp-transport-loopback [<ice-candidate-type> ...]
    
### sctp-redirect-transport

The SCTP redirect transport tool starts an SCTP redirect transport on top of an
established DTLS transport to relay SCTP messages from and to a third party.
This tool has been developed to be able to test data channel implementations
without having to write the required DTLS and ICE stacks. An example of such a
testing tool is [dctt][dctt] which uses the kernel SCTP stack of FreeBSD.

Usage:

    sctp-redirect-transport <0|1 (ice-role)> <redirect-ip> <redirect-port>
                            [<sctp-port>] [<maximum-message-size>]
                            [<ice-candidate-type> ...]

### data-channel-sctp-loopback

The data channel SCTP loopback tool creates several data channels on top of an
abstracted SCTP data transport. As soon as a data channel is open, a message
will be sent to the other peer. Furthermore, another message will be sent on a
specific channel after a brief timeout.

To verify that a data channels opens, wait for the following line:

    (<client>) Data channel open: <channel-label>
    
The tool will send some large (16 MiB) test data to the other peer depending on
the ICE role. We are able to do this because RAWRTC handles data channel
messages correctly and does not have a maximum message size limitation compared
to most other implementations (check out
[this article][demystifying-webrtc-dc-size-limit] for a detailed explanation).

Usage:

    data-channel-sctp-loopback [<ice-candidate-type> ...]

### data-channel-sctp

The data channel SCTP tool creates several data channels on top of an
abstracted SCTP data transport:

1. A pre-negotiated data channel with the label `cat-noises` and the id `0`
   that is reliable and ordered. In the WebRTC JS API, the channel would be
   created by invoking:
   
   ```js
   peerConnection.createDataChannel('cat-noises', {
       ordered: true,
       id: 0
   });
   ```

2. A data channel with the label `bear-noises` that is reliable but unordered.
   In the WebRTC JS API, the channel would be created by invoking:
   
   ```js
   peerConnection.createDataChannel('bear-noises', {
       ordered: true,
       maxRetransmits: 0
   });
   ```

To establish a connection with another peer, the following procecure must be
followed:

1. The JSON blob after `Local Parameters:` must be pasted into the other peer
   you want to establish a connection with. This can be either a browser
   instance that uses the [WebRTC-RAWRTC browser tool][webrtc-rawrtc] or
   another instance of this tool.

2. The other peer's local parameters in form of a JSON blob must be pasted into
   this tool's instance.

3. Once you've pasted the local parameters into each other's instance, the peer
   connection can be established by pressing *Enter* in both instances (click
   the *Start* button in the browser).

The tool will send some test data to the other peer depending on the ICE role.
However, the browser tool behaves a bit differently. Check the log output of
the tool instances (console output in the browser) to see what data has been
sent and whether it has been received successfully.

In the browser, you can use the created data channels by accessing
`peer.dc['<channel-name>']`, for example:

```js
peer.dc['example-channel'].send('RAWR!')
```

Usage:

    data-channel-sctp <0|1 (ice-role)> [<sctp-port>] [<ice-candidate-type> ...]

### data-channel-sctp-echo

The data channel SCTP echo tool behaves just like any other echo server: It
echoes received data on any data channel back to the sender.

The necessary peer connection establishment steps are identical to the ones
described for the [data-channel-sctp](#data-channel-sctp) tool.

Usage:

    data-channel-sctp-echo <0|1 (ice-role)> [<sctp-port>] [<ice-candidate-type> ...]

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
[sdp]: https://tools.ietf.org/html/draft-ietf-rtcweb-sdp-04
[ip-handling]: https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-03

[git]: (https://git-scm.com)
[cmake]: https://cmake.org
[meson]: https://github.com/mesonbuild/meson
[ninja]: https://ninja-build.org

[webrtc-rawrtc]: https://github.com/rawrtc/rawrtc/blob/master/htdocs/webrtc-rawrtc.html
[dctt]: https://github.com/nplab/dctt
[demystifying-webrtc-dc-size-limit]: https://lgrahl.de/articles/demystifying-webrtc-dc-size-limit.html
