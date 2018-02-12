'use strict';

/**
 * A copy & paste signalling implementation.
 *
 * Tightly coupled with the WebRTC peer connection class.
 */
class CopyPasteSignaling {
    constructor(pc = null) {
        this._pc = pc;
        this.pending_inbound_messages = [];
        this.localIceCandidatesSent = false;
        this.remoteIceCandidatesReceived = false;
        this._onLocalDescriptionUpdate = null;
        this._onRemoteDescriptionUpdate = null;
    }

    set pc(pc) {
        this._pc = pc;

        // Process all pending inbound messages
        for (const message of this.pending_inbound_messages) {
            this.receiveMessage(message.type, message.value);
        }
    }

    set onLocalDescriptionUpdate(callback) {
        this._onLocalDescriptionUpdate = callback;
    }

    set onRemoteDescriptionUpdate(callback) {
        this._onRemoteDescriptionUpdate = callback;
    }

    handleLocalDescription(description, complete = false) {
        console.log('Local description:', description);

        // Send local description
        this.sendMessage('description', description);
        if (complete) {
            this.localIceCandidatesSent = true;
            this.maybeClose();
            console.info('Local description complete');
        }

        // Call 'update'
        if (this._onLocalDescriptionUpdate !== null) {
            this._onLocalDescriptionUpdate(this._pc.localDescription);
        }
    }

    async handleRemoteDescription(description, complete = false) {
        // Set remote description
        console.log('Setting remote description');
        await this._pc.setRemoteDescription(description);
        console.log('Remote description:', this._pc.remoteDescription);
        if (complete) {
            this.remoteIceCandidatesReceived = true;
            this.maybeClose();
            console.info('Remote description complete');
        }

        // Call 'update' (remote description)
        if (this._onRemoteDescriptionUpdate !== null) {
            this._onRemoteDescriptionUpdate(this._pc.remoteDescription);
        }

        // Create answer (if required)
        if (!this._pc._offering) {
            console.log(name, 'Creating answer');
            description = await this._pc.createAnswer();

            // Apply local description
            await this._pc.setLocalDescription(description);
            this.handleLocalDescription(description);
        }
    }

    handleLocalCandidate(candidate) {
        console.log('Local ICE candidate:', candidate);

        // Send local candidate
        this.sendMessage('candidate', candidate);

        // Special handling for last candidate
        if (candidate === null) {
            this.localIceCandidatesSent = true;
            this.maybeClose();
            console.info('Local description complete');
        }

        // Call 'update' (local description)
        if (this._onLocalDescriptionUpdate !== null) {
            this._onLocalDescriptionUpdate(this._pc.localDescription);
        }
    }

    async handleRemoteCandidate(candidate) {
        console.log('Remote ICE candidate:', candidate);
        if (candidate !== null) {
            // Add remote candidate (if any)
            await this._pc.addIceCandidate(candidate);
        } else {
            // Special handling for last candidate
            this.remoteIceCandidatesReceived = true;
            this.maybeClose();
            console.info('Remote description complete');
        }

        // Call 'update' (remote description)
        if (this._onRemoteDescriptionUpdate !== null) {
            this._onRemoteDescriptionUpdate(this._pc.remoteDescription);
        }
    }

    sendMessage(type, value) {
        // Does nothing by default
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
                this.handleRemoteCandidate(value).catch((error) => console.error(error));
                break;
            default:
                console.warn('Unknown message type:', type);
                break;
        }
    }

    maybeClose() {
        // Close once all messages have been exchanged
        if (this.localIceCandidatesSent && this.remoteIceCandidatesReceived) {
            console.log('Closing signalling channel');
            this.close();
        }
    }

    close() {
        // Does nothing by default
    }
}

/**
 * A signalling implementation intended for this signalling server:
 * https://github.com/rawrtc/rawrtc-terminal-demo/tree/master/signaling
 *
 * Tightly coupled with the WebRTC peer connection class.
 *
 * Example: `ws://localhost/meow/0` when offering, and
 *          `ws://localhost/meow/1` when answering.
 */
class WebSocketSignaling extends CopyPasteSignaling {
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
