#include "transport.h"
#include "../ice_gatherer/gatherer.h"
#include <rawrtc/ice_transport.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <rew.h>

/*
 * Get the current ICE role of the ICE transport.
 * Return `RAWRTC_CODE_NO_VALUE` code in case the ICE role has not been
 * determined yet.
 */
enum rawrtc_code rawrtc_ice_transport_get_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        struct rawrtc_ice_transport* const transport
) {
    enum ice_role re_role;
    enum rawrtc_code error;
    enum rawrtc_ice_role role;

    // Check arguments
    if (!rolep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get libre role from ICE instance
    re_role = trice_local_role(transport->gatherer->ice);

    // Translate role
    error = rawrtc_re_ice_role_to_ice_role(&role, re_role);
    if (error) {
        return error;
    }

    // Unknown?
    if (re_role == ICE_ROLE_UNKNOWN) {
        return RAWRTC_CODE_NO_VALUE;
    } else {
        // Set pointer
        *rolep = role;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current state of the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_get_state(
        enum rawrtc_ice_transport_state* const statep, // de-referenced
        struct rawrtc_ice_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state & done
    *statep = transport->state;
    return RAWRTC_CODE_SUCCESS;
}
