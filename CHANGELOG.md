# Changelog

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



[0.3.0]: https://github.com/rawrtc/rawrtc/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/rawrtc/rawrtc/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/rawrtc/rawrtc/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/rawrtc/rawrtc/compare/bd9d1ef15d008fdc24b4d5e3158e775a03ffec16...v0.2.0
