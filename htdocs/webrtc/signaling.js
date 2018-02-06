'use strict';

/**
 * An abstract signalling implementation. Tightly coupled with the
 * WebRTC peer connection class.
 */
class Signaling {
    constructor(pc = null) {
        this._pc = pc;
        this.name = 'unknown';
        this.pending_inbound_messages = [];
        this.localIceCandidatesSent = false;
        this.remoteIceCandidatesReceived = false;
    }

    set pc(pc) {
        this._pc = pc;
        this.name = pc._name;
        for (const message of this.pending_inbound_messages) {
            this.receiveMessage(message.type, message.value);
        }
    }

    handleLocalDescription(description) {
        console.log(this.name, 'Sending remote description:', description);
        this.sendMessage('description', description);
    }

    async handleRemoteDescription(description) {
        console.log(this.name, 'Received remote description:', description);
        await this._pc.setRemoteDescription(description);

        // Create answer (if required)
        if (!this._pc._offering) {
            console.log(name, 'Creating answer');
            description = await this._pc.createAnswer();
            await this._pc.setLocalDescription(description);
            this.handleLocalDescription(description);
        }
    }

    handleLocalCandidate(candidate) {
        console.log(this.name, 'Sending local ICE candidate:', candidate);
        this.sendMessage('candidate', candidate);
        if (candidate === null) {
            this.localIceCandidatesSent = true;
            this.maybeClose();
        }
    }

    handleRemoteCandidate(candidate) {
        console.log(this.name, 'Received remote ICE candidate:', candidate);
        if (candidate !== null) {
            this._pc.addIceCandidate(candidate);
        } else {
            this.remoteIceCandidatesReceived = true;
            this.maybeClose();
        }
    }

    sendMessage(type, value) {
        console.error(this.name, 'You need to implement this!');
    }

    receiveMessage(type, value) {
        // Hold back messages until peer connection is set
        if (this._pc === null) {
            this.pending_inbound_messages.push({type: type, value: value});
        }

        // Handle message
        switch (type) {
            case 'description':
                this.handleRemoteDescription(value).catch((error) => console.error(error));
                break;
            case 'candidate':
                this.handleRemoteCandidate(value);
                break;
            default:
                console.warn(this.name, 'Unknown message type:', type);
                break;
        }
    }

    maybeClose() {
        if (this.localIceCandidatesSent && this.remoteIceCandidatesReceived) {
            console.log(this.name, 'Closing signalling channel');
            this.close();
        }
    }

    close() {
        // Does nothing by default
    }
}

/**
 * An signalling implementation where offer and answer need to be
 * copied and pasted by hand.
 */
class CopyPasteSignaling extends Signaling {
    constructor(element, pc = null) {
        super(pc);
        this.element = element;
    }

    sendMessage(type, value) {

    }
}

/**
 * A signalling implementation intended for this signalling server:
 * https://github.com/rawrtc/rawrtc-terminal-demo/tree/master/signaling
 *
 * Example: `ws://localhost/meow/0` when offering, and
 *          `ws://localhost/meow/1` when answering.
 */
class WebSocketSignaling extends Signaling {
    constructor(wsUrl, pc = null) {
        super(pc);
        this.pending_outbound_messages = [];

        const ws = new WebSocket(wsUrl);
        ws.onopen = () => {
            console.log('WS open');
            for (const message of this.pending_outbound_messages) {
                this.sendMessage(message.type, message.value);
            }
        };
        ws.onclose = () => {
            console.log('WS closed');
        };
        ws.onerror = (event) => {
            console.error('WS error:', event);
        };
        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            if (!('type' in message)) {
                console.warn("Invalid message, did not contain a 'type' field");
                return;
            }
            this.receiveMessage(message.type, message.value || null);
        };

        // Store web socket instance
        this.ws = ws;
    }

    sendMessage(type, value) {
        // Cache if not open, yet.
        if (this.ws.readyState !== 1) {
            this.pending_outbound_messages.push({type: type, value: value});
            return;
        }

        // Send
        this.ws.send(JSON.stringify({
            type: type,
            value: value
        }));
    }

    close() {
        super.close();
        this.ws.close();
    }
}
