# Changelog

## [0.5.2] (2021-09-20)

* Fix usrsctp dependency (#154)

## [0.5.1] (2019-08-15)

* Re-enable peer reflexive candidates (#141)

## [0.5.0] (2019-08-15)

* Fix BoringSSL compatibility (#139)
* Calculate ICE candidate priority (#140)
* Use [upstream usrsctp](https://github.com/sctplab/usrsctp/)
* Expose more transport parameters (#146)
  - Add getter/setter for send/receiver buffer length
  - Add getter/setter for congestion control algorithm
  - Add getter/setter for MTU

## [0.4.0] (2019-03-19)

* Replace CMake with Meson build system
  - This finally allowed us to get rid of the dependencies script :tada:
* Internal restructuring of source files

## [0.3.0] (2019-03-02)

* Split the stack into three separate entities (major)
  - RAWRTC (this repository) contains the WebRTC/ORTC API, the ICE/DTLS stack
    and bindings to the data channel implementation.
  - [RAWRTCDC](https://github.com/rawrtc/rawrtc-data-channel) contains the data
    channel implementation
  - [RAWRTCC](https://github.com/rawrtc/rawrtc-common) contains common
    functionality required by both RAWRTC and RAWRTCDC
* Added a gathering timeout
* Fixed various issues with the ICE transport states

## [0.2.2] (2018-04-14)

* Fixed parsing the DTLS role in the peer connection API

## [0.2.1] (2018-02-26)

* Fixed missing cast in examples leading to issues on specific platforms (such
  as ARM)

## [0.2.0] (2018-02-12)

* Initial release of RAWRTC



[0.5.2]: https://github.com/rawrtc/rawrtc/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/rawrtc/rawrtc/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/rawrtc/rawrtc/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/rawrtc/rawrtc/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/rawrtc/rawrtc/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/rawrtc/rawrtc/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/rawrtc/rawrtc/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rawrtc/rawrtc/compare/bd9d1ef15d008fdc24b4d5e3158e775a03ffec16...v0.2.0
