#pragma once
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_ice_candidate;
struct rawrtc_ice_gatherer;
struct rawrtc_ice_parameters;

/*
 * ICE role.
 */
enum rawrtc_ice_role {
    RAWRTC_ICE_ROLE_UNKNOWN = ICE_ROLE_UNKNOWN,
    RAWRTC_ICE_ROLE_CONTROLLING = ICE_ROLE_CONTROLLING,
    RAWRTC_ICE_ROLE_CONTROLLED = ICE_ROLE_CONTROLLED,
};

/*
 * ICE transport state.
 */
enum rawrtc_ice_transport_state {
    RAWRTC_ICE_TRANSPORT_STATE_NEW,
    RAWRTC_ICE_TRANSPORT_STATE_CHECKING,
    RAWRTC_ICE_TRANSPORT_STATE_CONNECTED,
    RAWRTC_ICE_TRANSPORT_STATE_COMPLETED,
    RAWRTC_ICE_TRANSPORT_STATE_DISCONNECTED,
    RAWRTC_ICE_TRANSPORT_STATE_FAILED,
    RAWRTC_ICE_TRANSPORT_STATE_CLOSED,
};

/*
 * ICE transport.
 */
struct rawrtc_ice_transport;

/*
 * ICE transport state change handler.
 */
typedef void (*rawrtc_ice_transport_state_change_handler)(
    enum rawrtc_ice_transport_state const state,
    void* const arg
);

/*
 * ICE transport pair change handler.
 */
typedef void (*rawrtc_ice_transport_candidate_pair_change_handler)(
    struct rawrtc_ice_candidate* const local, // read-only
    struct rawrtc_ice_candidate* const remote, // read-only
    void* const arg
);

/*
 * Create a new ICE transport.
 * `*transportp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_transport_create(
    struct rawrtc_ice_transport** const transportp, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer, // referenced, nullable
    rawrtc_ice_transport_state_change_handler const state_change_handler, // nullable
    rawrtc_ice_transport_candidate_pair_change_handler const candidate_pair_change_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_start(
    struct rawrtc_ice_transport* const transport,
    struct rawrtc_ice_gatherer* const gatherer, // referenced
    struct rawrtc_ice_parameters* const remote_parameters, // referenced
    enum rawrtc_ice_role const role
);

/*
 * Stop and close the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_stop(
    struct rawrtc_ice_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * rawrtc_ice_transport_get_ice_gatherer
 */

/*
 * Get the current ICE role of the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_get_role(
    enum rawrtc_ice_role* const rolep, // de-referenced
    struct rawrtc_ice_transport* const transport
);

/*
 * TODO
 * rawrtc_ice_transport_get_component
 */

/*
 * Get the current state of the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_get_state(
    enum rawrtc_ice_transport_state* const statep, // de-referenced
    struct rawrtc_ice_transport* const transport
);

/*
 * rawrtc_ice_transport_get_remote_candidates
 * rawrtc_ice_transport_get_selected_candidate_pair
 * rawrtc_ice_transport_get_remote_parameters
 * rawrtc_ice_transport_create_associated_transport (unsupported)
 */

/*
 * Add a remote candidate ot the ICE transport.
 * Note: 'candidate' must be NULL to inform the transport that the
 * remote site finished gathering.
 */
enum rawrtc_code rawrtc_ice_transport_add_remote_candidate(
    struct rawrtc_ice_transport* const transport,
    struct rawrtc_ice_candidate* candidate // nullable
);

/*
 * Set the remote candidates on the ICE transport overwriting all
 * existing remote candidates.
 */
enum rawrtc_code rawrtc_ice_transport_set_remote_candidates(
    struct rawrtc_ice_transport* const transport,
    struct rawrtc_ice_candidate* const candidates[], // referenced (each item)
    size_t const n_candidates
);

/* TODO (from RTCIceTransport interface)
 * rawrtc_ice_transport_set_state_change_handler
 * rawrtc_ice_transport_set_candidate_pair_change_handler
 */

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * rawrtc_ice_transport_state_to_name(
    enum rawrtc_ice_transport_state const state
);

/*
 * Translate an ICE role to str.
 */
char const * rawrtc_ice_role_to_str(
    enum rawrtc_ice_role const role
);

/*
 * Translate a str to an ICE role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_role(
    enum rawrtc_ice_role* const rolep, // de-referenced
    char const* const str
);
