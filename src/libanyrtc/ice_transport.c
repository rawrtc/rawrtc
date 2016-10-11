#include <anyrtc.h>
#include "ice_transport.h"

#define DEBUG_MODULE "ice-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const anyrtc_ice_transport_state_to_name(
        enum anyrtc_ice_transport_state state
) {
    switch (state) {
        case ANYRTC_ICE_TRANSPORT_NEW:
            return "new";
        case ANYRTC_ICE_TRANSPORT_CHECKING:
            return "checking";
        case ANYRTC_ICE_TRANSPORT_CONNECTED:
            return "connected";
        case ANYRTC_ICE_TRANSPORT_COMPLETED:
            return "completed";
        case ANYRTC_ICE_TRANSPORT_DISCONNECTED:
            return "disconnected";
        case ANYRTC_ICE_TRANSPORT_FAILED:
            return "failed";
        case ANYRTC_ICE_TRANSPORT_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_ice_transport_destroy(void* arg) {
    struct anyrtc_ice_transport* transport = arg;

    // Dereference
    mem_deref(transport->gatherer);
}

/*
 * Create a new ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_create(
        struct anyrtc_ice_transport** const transportp, // de-referenced
        struct anyrtc_ice_gatherer* const gatherer, // referenced, nullable
        anyrtc_ice_transport_state_change_handler* const state_change_handler, // nullable
        anyrtc_ice_transport_candidate_pair_change_handler* const candidate_pair_change_handler, // nullable
        void* const arg // nullable
) {
    struct anyrtc_ice_transport* transport;

    // Check arguments
    if (!transportp || !gatherer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check ICE gatherer state
    // TODO: Check if gatherer.component is RTCP -> invalid state
    if (gatherer->state == ANYRTC_ICE_GATHERER_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Allocate
    transport = mem_alloc(sizeof(struct anyrtc_ice_transport), anyrtc_ice_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = ANYRTC_ICE_TRANSPORT_NEW;
    transport->gatherer = mem_ref(gatherer);
    transport->state_change_handler = state_change_handler;
    transport->candidate_pair_change_handler = candidate_pair_change_handler;
    transport->arg = arg;
    transport->role = ANYRTC_ICE_ROLE_UNKNOWN;

    // Set pointer
    *transportp = transport;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Start the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_start(
        struct anyrtc_ice_transport* const transport,
        struct anyrtc_ice_gatherer* const gatherer, // referenced
        struct anyrtc_ice_parameters const * const remote_parameters, // copied
        enum anyrtc_ice_role const role
) {
    // TODO: Implement
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}

/*
 * Stop and close the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_stop(
        struct anyrtc_ice_transport* const transport
) {
    // TODO: Implement
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
