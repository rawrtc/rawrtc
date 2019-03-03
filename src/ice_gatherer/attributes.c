#include "gatherer.h"
#include <rawrtc/ice_gatherer.h>
#include <rawrtcc/code.h>

/*
 * Get the current state of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_state(
        enum rawrtc_ice_gatherer_state* const statep, // de-referenced
        struct rawrtc_ice_gatherer* const gatherer
) {
    // Check arguments
    if (!statep || !gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = gatherer->state;
    return RAWRTC_CODE_SUCCESS;
}
