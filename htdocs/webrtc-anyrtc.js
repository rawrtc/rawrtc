'use strict';

class Peer {
    constructor() {
        this.pc = null;
        this.dc = null;
        this.localCandidates = [];
        this.localDescription = null;
        this.remoteDescription = null;
        var _waitGatheringComplete = {};
        _waitGatheringComplete.promise = new Promise((resolve, reject) => {
            _waitGatheringComplete.resolve = resolve;
            _waitGatheringComplete.reject = reject;
        });
        this._waitGatheringComplete = _waitGatheringComplete;
    }

    createPeerConnection() {
        if (this.pc) {
            console.warn('RTCPeerConnection already created');
            return;
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

        this.pc = pc;
    }

    createDataChannel() {
        if (this.dc) {
            console.warn('Data channel already created');
            return;
        }

        // Create data channel
        var dc = this.pc.createDataChannel('example-channel', {
            ordered: true
        });

        // Bind data channel events
        dc.onopen = function(event) {
            console.log('Data channel', dc.id, 'open');
            // Send 'hello'
            dc.send('Hello from WebRTC on', navigator.userAgent);
        };
        dc.onbufferedamountlow = function(event) {
            console.log('Data channel', dc.id, 'buffered amount low');
        };
        dc.onerror = function(event) {
            console.error('Data channel', dc.id, 'error:', event);
        };
        dc.onclose = function(event) {
            console.log('Data channel', dc.id, 'closed');
        };
        dc.onmessage = function(event) {
            console.info('Data channel', dc.id, 'message:', event.data);
        };

        this.dc = dc;
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
            };

            // Split sections
            var sections = SDPUtils.splitSections(this.localDescription.sdp);
            var session = sections.shift();

            // Go through media sections
            sections.forEach(function(mediaSection, sdpMLineIndex) {
                // TODO: Ignore anything else but data transports

                // Get ICE parameters
                if (!parameters.iceParameters) {
                    parameters.iceParameters = SDPUtils.getIceParameters(mediaSection, session);
                }

                // Get DTLS parameters
                if (!parameters.dtlsParameters) {
                    parameters.dtlsParameters = SDPUtils.getDtlsParameters(mediaSection, session);
                }
            });

            // ICE lite parameter
            if (!parameters.iceParameters || !parameters.dtlsParameters) {
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

    setRemoteParameters(parameters, type, sctpPort = 5000, localMid = 0) {
        return new Promise((resolve, reject) => {
            if (this.remoteDescription) {
                resolve(this.remoteDescription);
                return;
            }

            if (!this.pc) {
                console.error('Must create RTCPeerConnection instance');
                return;
            }

            // Write SDP
            var sdp = SDPUtils.writeSessionBoilerplate();

            // Write media section
            sdp += 'a=msid-semantic: WMS\r\n'; // magic pixie dust
            sdp += 'm=application 9 DTLS/SCTP ' + sctpPort + '\r\n';
            sdp += 'c=IN IP4 0.0.0.0\r\n';
            sdp += SDPUtils.writeIceParameters(parameters.iceParameters);
            sdp += SDPUtils.writeDtlsParameters(parameters.dtlsParameters);
            sdp += 'a=mid:' + localMid + '\r\n';
            sdp += 'a=sctpmap:' + sctpPort + ' webrtc-datachannel 1024\r\n';

            // Set remote description
            this.pc.setRemoteDescription({type: type, sdp: sdp})
            .then(() => {
                console.log('Remote description:\n' + this.pc.remoteDescription.sdp);
                this.remoteDescription = this.pc.remoteDescription;
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

    setRemoteParameters(parameters, sctpPort = 5000, localMid = 0) {
        super.setRemoteParameters(parameters, 'answer', sctpPort, localMid);
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

    setRemoteParameters(parameters, sctpPort = 5000, localMid = 0) {
        super.setRemoteParameters(parameters, 'offer', sctpPort, localMid);
    }
}
