#pragma once

/*
 * Signalling state.
 */
enum rawrtc_signaling_state {
    RAWRTC_SIGNALING_STATE_STABLE,
    RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER,
    RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER,
    RAWRTC_SIGNALING_STATE_HAVE_LOCAL_PROVISIONAL_ANSWER,
    RAWRTC_SIGNALING_STATE_HAVE_REMOTE_PROVISIONAL_ANSWER,
    RAWRTC_SIGNALING_STATE_CLOSED,
};

/*
 * Peer connection state.
 */
enum rawrtc_peer_connection_state {
    RAWRTC_PEER_CONNECTION_STATE_NEW,
    RAWRTC_PEER_CONNECTION_STATE_CONNECTING,
    RAWRTC_PEER_CONNECTION_STATE_CONNECTED,
    RAWRTC_PEER_CONNECTION_STATE_DISCONNECTED,
    RAWRTC_PEER_CONNECTION_STATE_FAILED,
    RAWRTC_PEER_CONNECTION_STATE_CLOSED,
};

/*
 * Get the corresponding name for a signaling state.
 */
char const* rawrtc_signaling_state_to_name(enum rawrtc_signaling_state const state);

/*
 * Get the corresponding name for a peer connection state.
 */
char const* rawrtc_peer_connection_state_to_name(enum rawrtc_peer_connection_state const state);
