'use strict';

class Peer {
    constructor() {
        this.pc = null;
        this.localMid = null;
        this.localCandidates = [];
        this.localParameters = null;
        this.localDescription = null;
        this.remoteParameters = null;
        this.remoteDescription = null;
        var _waitGatheringComplete = {};
        _waitGatheringComplete.promise = new Promise((resolve, reject) => {
            _waitGatheringComplete.resolve = resolve;
            _waitGatheringComplete.reject = reject;
        });
        this._waitGatheringComplete = _waitGatheringComplete;
        this.dc = {}
    }

    createPeerConnection() {
        if (this.pc) {
            console.warn('RTCPeerConnection already created');
            return this.pc;
        }

        var self = this;

        // Create peer connection
        var pc = new RTCPeerConnection({
            iceServers: [{
                urls: 'stun:stun.l.google.com:19302'
            }]
        });

        // Bind peer connection events
        pc.onnegotiationneeded = function(event) {
            console.log('Negotiation needed')
        };
        pc.onicecandidate = function(event) {
            if (event.candidate) {
                console.log('Gathered candidate:', event.candidate);
                self.localCandidates.push(event.candidate);
            } else {
                console.log('Gathering complete');
                self._waitGatheringComplete.resolve();
            }
        };
        pc.onicecandidateerror = function(event) {
            console.error('ICE candidate error:', event.errorText);
        };
        pc.onsignalingstatechange = function(event) {
            console.log('Signaling state changed to:', pc.signalingState);
        };
        pc.oniceconnectionstatechange = function(event) {
            console.log('ICE connection state changed to:', pc.iceConnectionState);
        };
        pc.onicegatheringstatechange = function(event) {
            console.log('ICE gathering state changed to:', pc.iceGatheringState);
        };
        pc.onconnectionstatechange = function(event) {
            console.log('Connection state changed to:', pc.connectionState);
        };
        pc.ondatachannel = function(event) {
            self.createDataChannel(event.channel);
        };

        this.pc = pc;
        return pc;
    }

    createDataChannel(dc) {
        // Create data channel
        dc = (typeof dc !== 'undefined') ? dc : this.pc.createDataChannel('example-channel', {
            ordered: true
        });

        // Bind data channel events
        dc.onopen = function(event) {
            console.log('Data channel', dc.label, '(', dc.id, ')', 'open');
            // Send 'hello'
            dc.send('Hello from WebRTC on', navigator.userAgent);
        };
        dc.onbufferedamountlow = function(event) {
            console.log('Data channel', dc.label, '(', dc.id, ')', 'buffered amount low');
        };
        dc.onerror = function(event) {
            console.error('Data channel', dc.label, '(', dc.id, ')', 'error:', event);
        };
        dc.onclose = function(event) {
            console.log('Data channel', dc.label, '(', dc.id, ')', 'closed');
        };
        dc.onmessage = function(event) {
            var length = event.data.size || event.data.byteLength || event.data.length;
            console.info('Data channel', dc.label, '(', dc.id, ')', 'message size:', length);
        };

        // Store channel
        this.dc[dc.label] = dc;

        return dc;
    }

    getLocalParameters() {
        return new Promise((resolve, reject) => {
            var error;
            var self = this;

            if (!this.localDescription) {
                error = 'Must create offer/answer';
                console.error(error);
                reject(error);
                return;
            }

            // Initialise parameters
            var parameters = {
                iceParameters: null,
                iceCandidates: [],
                dtlsParameters: null,
                sctpParameters: null,
            };

            // Split sections
            var sections = SDPUtils.splitSections(this.localDescription.sdp);
            var session = sections.shift();

            // Go through media sections
            sections.forEach(function(mediaSection, sdpMLineIndex) {
                // TODO: Ignore anything else but data transports

                // Get mid
                // TODO: This breaks with multiple transceivers
                if (!self.localMid) {
                    var mid = SDPUtils.matchPrefix(mediaSection, 'a=mid:');
                    if (mid.length > 0) {
                        self.localMid = mid[0].substr(6);
                    }
                }

                // Get ICE parameters
                if (!parameters.iceParameters) {
                    parameters.iceParameters = SDPUtils.getIceParameters(mediaSection, session);
                }

                // Get DTLS parameters
                if (!parameters.dtlsParameters) {
                    parameters.dtlsParameters = SDPUtils.getDtlsParameters(mediaSection, session);
                }

                // Get SCTP parameters
                if (!parameters.sctpParameters) {
                    parameters.sctpParameters = SDPUtils.getSctpCapabilities(mediaSection, session);
                    parameters.sctpParameters.port = SDPUtils.getSctpPort(mediaSection, session);
                }
            });

            // ICE lite parameter
            if (!parameters.iceParameters
                    || !parameters.dtlsParameters
                    || !parameters.sctpParameters) {
                error = 'Could not retrieve required parameters from local description';
                console.error(error);
                reject(error);
                return;
            }
            parameters.iceParameters.iceLite =
                SDPUtils.matchPrefix(session, 'a=ice-lite').length > 0;

            // Get ICE candidates
            this._waitGatheringComplete.promise.then(() => {
                // Add ICE candidates
                for (var sdpCandidate of self.localCandidates) {
                    var candidate = SDPUtils.parseCandidate(sdpCandidate.candidate);
                    parameters.iceCandidates.push(candidate);
                }

                // Add ICE candidate complete sentinel
                // parameters.iceCandidates.push({complete: true}); // TODO

                // Done
                resolve(parameters);
            });
        });
    }

    setRemoteParameters(parameters, type, localMid = null) {
        return new Promise((resolve, reject) => {
            if (this.remoteDescription) {
                resolve(this.remoteDescription);
                return;
            }

            if (!this.pc) {
                console.error('Must create RTCPeerConnection instance');
                return;
            }

            if (!localMid) {
                localMid = this.localMid;
            }
            this.remoteParameters = parameters;

            // Translate DTLS role
            // TODO: This somehow didn't make it into SDPUtils
            var setupType;
            switch (parameters.dtlsParameters.role) {
                case 'client':
                    setupType = 'active';
                    break;
                case 'server':
                    setupType = 'passive';
                    break;
                default:
                    // We map 'offer' to 'controlling' and 'answer' to 'controlled',
                    // so rawrtc will take 'server' if offering and 'client' if answering
                    // as specified by the ORTC spec
                    switch (type) {
                        case 'offer':
                            // WebRTC requires actpass in offer
                            setupType = 'actpass';
                            break;
                        case 'answer':
                            setupType = 'active';
                            break;
                    }
                    break;
            }

            // Write session section
            var sdp = SDPUtils.writeSessionBoilerplate();
            sdp += 'a=group:BUNDLE ' + localMid + '\r\n';
            sdp += 'a=ice-options:trickle\r\n';
            if (parameters.iceParameters.iceLite) {
                sdp += 'a=ice-lite\r\n';
            }

            // Write media section
            // TODO: Replace
            // sdp += 'm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n'; // (03)
            sdp += 'm=application 9 DTLS/SCTP ' + parameters.sctpParameters.port + '\r\n'; // (01)
            sdp += 'c=IN IP4 0.0.0.0\r\n';
            sdp += 'a=mid:' + localMid + '\r\n';
            sdp += 'a=sendrecv\r\n';

            // SCTP part
            sdp += SDPUtils.writeSctpCapabilities(parameters.sctpParameters);
            sdp += SDPUtils.writeSctpPort(parameters.sctpParameters.port);
            sdp += 'a=sctpmap:' + parameters.sctpParameters.port + ' webrtc-datachannel 65535\r\n'; // (01)

            // DTLS part
            sdp += SDPUtils.writeDtlsParameters(parameters.dtlsParameters, setupType);

            // ICE part
            sdp += 'a=connection:new\r\n'; // (03)
            sdp += SDPUtils.writeIceParameters(parameters.iceParameters);

            // Done
            console.log('Remote description:\n' + sdp);

            // Set remote description
            this.pc.setRemoteDescription({type: type, sdp: sdp})
            .then(() => {
                console.log('Remote description:\n' + this.pc.remoteDescription.sdp);
                this.remoteDescription = this.pc.remoteDescription;

                // Add ICE candidates
                for (var iceCandidate of parameters.iceCandidates) {
                    // Add component which ORTC doesn't have
                    // Note: We choose RTP as it doesn't actually matter for us
                    iceCandidate.component = 1; // RTP

                    // Create
                    var candidate = new RTCIceCandidate({
                        candidate: SDPUtils.writeCandidate(iceCandidate),
                        sdpMLineIndex: 0, // TODO: Fix
                        sdpMid: localMid // TODO: Fix
                    });

                    // Add
                    console.log(candidate.candidate);
                    this.pc.addIceCandidate(candidate)
                    .then(() => {
                        console.log('Added remote candidate', candidate);
                    });
                }

                // It's trickle ICE, no need to wait for candidates to be added
                resolve();
            })
            .catch((error) => {
                reject(error);
            });
        });
    }

    start() {}
}

class ControllingPeer extends Peer {
    getLocalParameters() {
        return new Promise((resolve, reject) => {
            if (!this.pc) {
                var error = 'Must create RTCPeerConnection instance';
                console.error(error);
                reject(error);
                return;
            }

            var getLocalParameters = () => {
                // Return parameters
                super.getLocalParameters()
                .then((parameters) => {
                    this.localParameters = parameters;
                    resolve(parameters);
                })
                .catch((error) => {
                    reject(error);
                });
            };

            // Create offer
            if (!this.localDescription) {
                this.pc.createOffer()
                .then((description) => {
                    return this.pc.setLocalDescription(description);
                })
                .then(() => {
                    console.log('Local description:\n' + this.pc.localDescription.sdp);
                    this.localDescription = this.pc.localDescription;
                    getLocalParameters();
                })
                .catch((error) => {
                    reject(error);
                });
            } else {
                getLocalParameters();
            }
        });
    }

    setRemoteParameters(parameters, localMid = null) {
        return super.setRemoteParameters(parameters, 'answer', localMid);
    }
}

class ControlledPeer extends Peer {
    getLocalParameters() {
        return new Promise((resolve, reject) => {
            var error;

            if (!this.pc) {
                error = 'Must create RTCPeerConnection instance';
                console.error(error);
                reject(error);
                return;
            }
            if (!this.remoteDescription) {
                error = 'Must have remote description';
                console.error(error);
                reject(error);
                return;
            }

            var getLocalParameters = () => {
                // Return parameters
                super.getLocalParameters()
                .then((parameters) => {
                    resolve(parameters);
                })
                .catch((error) => {
                    reject(error);
                });
            };

            // Create answer
            if (!this.localDescription) {
                this.pc.createAnswer()
                .then((description) => {
                    return this.pc.setLocalDescription(description);
                })
                .then(() => {
                    console.log('Local description:\n' + this.pc.localDescription.sdp);
                    this.localDescription = this.pc.localDescription;
                    getLocalParameters();
                });
            } else {
                getLocalParameters();
            }
        });
    }

    setRemoteParameters(parameters, localMid = null) {
        return super.setRemoteParameters(parameters, 'offer', localMid);
    }
}
