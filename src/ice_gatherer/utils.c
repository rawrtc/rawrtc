#include <rawrtc/ice_gatherer.h>

/*
 * Get the corresponding name for an ICE gatherer state.
 */
char const* rawrtc_ice_gatherer_state_to_name(enum rawrtc_ice_gatherer_state const state) {
    switch (state) {
        case RAWRTC_ICE_GATHERER_STATE_NEW:
            return "new";
        case RAWRTC_ICE_GATHERER_STATE_GATHERING:
            return "gathering";
        case RAWRTC_ICE_GATHERER_STATE_COMPLETE:
            return "complete";
        case RAWRTC_ICE_GATHERER_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}
