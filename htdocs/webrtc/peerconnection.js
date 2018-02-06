'use strict';

/**
 * A WebRTC peer connection helper. Tightly coupled with the signaling
 * class.
 */
class WebRTCPeerConnection {
    constructor(signaling, configuration = null) {
        // Set default configuration (if none provided)
        if (configuration === null) {
            configuration = {
                iceServers: [{
                    urls: 'stun:stun.services.mozilla.com',
                }],
            };
        }

        // Store configuration & signalling instance
        this.signaling = signaling;
        this.configuration = configuration;
        this.pc = null;
        this.dcs = {};
        this._onLocalDescriptionComplete = null;
    }

    set onLocalDescriptionComplete(callback) {
        this._onLocalDescriptionComplete = callback;
    }

    start(offering) {
        // Already started?
        if (this.pc !== null) {
            console.error('Peer connection already started');
            return;
        }

        // Create peer connection and bind events
        const pc = new RTCPeerConnection(this.configuration);
        pc._offering = offering; // Meh!
        this.signaling.pc = pc;
        pc.onnegotiationneeded = async () => {
            console.log(name, 'Negotiation needed');

            // Create offer (if required)
            if (offering) {
                console.log(name, 'Creating offer');
                const description = await pc.createOffer();
                await pc.setLocalDescription(description);
                this.signaling.handleLocalDescription(description);
            }
        };
        pc.signalingstatechange = () => {
            console.log(name, 'Signaling state:', pc.signalingState);
        };
        pc.oniceconnectionstatechange = () => {
            console.log(name, 'ICE connection state:', pc.iceConnectionState);
        };
        pc.onicegatheringstatechange = () => {
            console.log(name, 'ICE gathering state:', pc.iceGatheringState);
        };
        pc.onconnectionstatechange = () => {
            console.log(name, 'Connection state:', pc.connectionState);
        };
        pc.onicecandidate = (event) => {
            if (event.candidate === null && this._onLocalDescriptionComplete !== null) {
                this._onLocalDescriptionComplete(pc.localDescription);
            }
            this.signaling.handleLocalCandidate(event.candidate);
        };
        pc.onicecandidateerror = (event) => {
            console.error(name, 'ICE candidate error:', event);
        };

        // Store peer connection
        window.pc = {
            pc: pc,
            dcs: {},
        };
        this.pc = pc;
    }

    createDataChannel(name, options = null) {
        const pc = this.pc;

        // Set default options (if none provided)
        if (options === null) {
            options = {
                negotiated: true,
                id: Object.keys(this.dcs).length + 1
            };
        }

        // Create data channel and bind events
        const dc = pc.createDataChannel(name, options);
        dc._name = pc._name + '.' + name; // Meh!
        dc.onopen = () => {
            console.log(dc._name, 'open');
        };
        dc.onclose = () => {
            console.log(dc._name, 'closed');
        };
        dc.onerror = (event) => {
            console.log(dc._name, 'error:', event);
        };
        dc.onbufferedamountlow = () => {
            console.log(dc._name, 'buffered amount low:', dc.bufferedAmount);
        };
        dc.onmessage = (event) => {
            const size = event.data.byteLength || event.data.size;
            console.log(dc._name, 'incoming message (' + size + ' bytes):', event);
        };

        // Store data channel and return
        this.dcs[name] = dc;
        return dc;
    }
}
