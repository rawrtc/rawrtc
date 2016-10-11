#include <anyrtc.h>
#include "ice_transport.h"
#include "utils.h"

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
    mem_deref(transport->remote_parameters);
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
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 */
static enum anyrtc_code set_state(
        struct anyrtc_ice_transport* const transport,
        enum anyrtc_ice_transport_state const state
) {
    // Set state
    transport->state = state;

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }

    return ANYRTC_CODE_SUCCESS;
}

/*
 * Start the ICE transport.
 * TODO https://github.com/w3c/ortc/issues/607
 */
enum anyrtc_code anyrtc_ice_transport_start(
        struct anyrtc_ice_transport* const transport,
        struct anyrtc_ice_gatherer* const gatherer, // referenced
        struct anyrtc_ice_parameters* const remote_parameters, // referenced
        enum anyrtc_ice_role const role
) {
    bool ice_transport_closed;
    bool ice_gatherer_closed;
    enum trice_role translated_role;
    enum anyrtc_code error;

    // Check arguments
    if (!transport || !gatherer || !remote_parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate parameters
    if (!remote_parameters->username_fragment || !remote_parameters->password) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Handle ICE lite
    if (remote_parameters->ice_lite) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // TODO: Check that components of ICE gatherer and ICE transport match

    // Check state
    ice_transport_closed = transport->state == ANYRTC_ICE_TRANSPORT_CLOSED;
    ice_gatherer_closed = gatherer->state == ANYRTC_ICE_GATHERER_CLOSED;
    if (ice_transport_closed || ice_gatherer_closed) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // TODO: Handle ICE restart when called again
    if (transport->state != ANYRTC_ICE_TRANSPORT_NEW) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check if gatherer instance is different
    // TODO https://github.com/w3c/ortc/issues/607
    if (transport->gatherer != gatherer) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // Set role (abort if unknown or something entirely weird)
    switch (role) {
        case ANYRTC_ICE_ROLE_CONTROLLING:
            translated_role = ROLE_CONTROLLING;
            break;
        case ANYRTC_ICE_ROLE_CONTROLLED:
            translated_role = ROLE_CONTROLLED;
            break;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
    error = anyrtc_code_re_translate(trice_set_role(transport->gatherer->ice, translated_role));
    if (error) {
        return error;
    }

    // New/first remote parameters?
    if (transport->remote_parameters != remote_parameters) {
        // Apply username fragment and password on trice
        error = anyrtc_code_re_translate(trice_set_remote_ufrag(
                transport->gatherer->ice, remote_parameters->username_fragment));
        if (error) {
            return error;
        }
        error = anyrtc_code_re_translate(trice_set_remote_pwd(
                transport->gatherer->ice, remote_parameters->password));
        if (error) {
            return error;
        }

        // Replace
        mem_deref(transport->remote_parameters);
        transport->remote_parameters = mem_ref(remote_parameters);
    }

    // Set state to checking
    // TODO: Get more states from trice
    error = set_state(transport, ANYRTC_ICE_TRANSPORT_CHECKING);
    if (error) {
        return error;
    }

    // TODO: Debug only
    DEBUG_PRINTF("%H", trice_debug, gatherer->ice);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Stop and close the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_stop(
        struct anyrtc_ice_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Already closed?
    if (transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return ANYRTC_CODE_SUCCESS;
    }

    // TODO: Remove remote candidates, role, username fragment and password from rew

    // TODO: Remove from RTCICETransportController (once we have it)

    return ANYRTC_CODE_SUCCESS;
}
