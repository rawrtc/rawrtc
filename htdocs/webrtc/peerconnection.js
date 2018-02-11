'use strict';

/**
 * A WebRTC peer connection helper. Tightly coupled with the signaling
 * class.
 */
class WebRTCPeerConnection {
    constructor(signaling, offering, configuration = null) {
        // Set default configuration (if none provided)
        if (configuration === null) {
            configuration = {
                iceServers: [{
                    urls: 'stun:stun.services.mozilla.com',
                }],
            };
        }

        // Create peer connection and bind events
        const pc = new RTCPeerConnection(configuration);
        pc._offering = offering; // Meh!
        signaling.pc = pc;
        pc.onnegotiationneeded = async () => {
            console.log('Negotiation needed');

            // Create offer (if required)
            if (offering) {
                console.log('Creating offer');
                const description = await pc.createOffer();
                await pc.setLocalDescription(description);
                signaling.handleLocalDescription(description);
            }
        };
        pc.signalingstatechange = () => {
            console.log('Signaling state:', pc.signalingState);
        };
        pc.oniceconnectionstatechange = () => {
            console.log('ICE connection state:', pc.iceConnectionState);
        };
        pc.onicegatheringstatechange = () => {
            console.log('ICE gathering state:', pc.iceGatheringState);
        };
        pc.onconnectionstatechange = () => {
            console.log('Connection state:', pc.connectionState);
        };
        pc.onicecandidate = (event) => {
            signaling.handleLocalCandidate(event.candidate);
        };
        pc.onicecandidateerror = (event) => {
            console.error('ICE candidate error:', event);
        };
        pc.ondatachannel = (event) => {
            const dc = event.channel;
            console.log('Incoming data channel:', dc.label);

            // Bind events
            this.bindDataChannelEvents(dc);
        };

        // Store configuration & signalling instance
        this.pc = pc;
        this.dcs = {};
    }

    createDataChannel(name, options = null) {
        const pc = this.pc;

        // Create data channel and bind events
        const dc = pc.createDataChannel(name, options);
        this.bindDataChannelEvents(dc);

        // Store data channel and return
        this.dcs[name] = dc;
        return dc;
    }

    bindDataChannelEvents(dc) {
        dc._name = dc.label; // Meh!
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
            console.log(dc._name, 'incoming message (' + size + ' bytes)');
        };
    }
}
