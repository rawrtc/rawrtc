#include <rawrtc.h>
#include "peer_connection_states.h"

/*
 * Get the corresponding name for a signaling state.
 */
char const * const rawrtc_signaling_state_to_name(
        enum rawrtc_signaling_state const state
) {
    switch (state) {
        case RAWRTC_SIGNALING_STATE_STABLE:
            return "stable";
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER:
            return "have-local-offer";
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER:
            return "have-remote-offer";
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_PROVISIONAL_ANSWER:
            return "have-local-pranswer";
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_PROVISIONAL_ANSWER:
            return "have-remote-pranswer";
        case RAWRTC_SIGNALING_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Get the corresponding name for a peer connection state.
 */
char const * const rawrtc_peer_connection_state_to_name(
        enum rawrtc_peer_connection_state const state
) {
    switch (state) {
        case RAWRTC_PEER_CONNECTION_STATE_NEW:
            return "new";
        case RAWRTC_PEER_CONNECTION_STATE_CONNECTING:
            return "connecting";
        case RAWRTC_PEER_CONNECTION_STATE_CONNECTED:
            return "connected";
        case RAWRTC_PEER_CONNECTION_STATE_DISCONNECTED:
            return "disconnected";
        case RAWRTC_PEER_CONNECTION_STATE_CLOSED:
            return "closed";
        case RAWRTC_PEER_CONNECTION_STATE_FAILED:
            return "failed";
        default:
            return "???";
    }
}
