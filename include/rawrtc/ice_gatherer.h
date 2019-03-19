#pragma once
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_ice_candidate;
struct rawrtc_ice_candidates;
struct rawrtc_ice_gather_options;
struct rawrtc_ice_parameters;

/*
 * ICE gatherer state.
 */
enum rawrtc_ice_gatherer_state {
    RAWRTC_ICE_GATHERER_STATE_NEW,
    RAWRTC_ICE_GATHERER_STATE_GATHERING,
    RAWRTC_ICE_GATHERER_STATE_COMPLETE,
    RAWRTC_ICE_GATHERER_STATE_CLOSED,
};

/*
 * ICE gatherer.
 */
struct rawrtc_ice_gatherer;

/*
 * ICE gatherer state change handler.
 */
typedef void (*rawrtc_ice_gatherer_state_change_handler)(
    enum rawrtc_ice_gatherer_state const state,  // read-only
    void* const arg);

/*
 * ICE gatherer error handler.
 */
typedef void (*rawrtc_ice_gatherer_error_handler)(
    struct rawrtc_ice_candidate* const candidate,  // read-only, nullable
    char const* const url,  // read-only
    uint16_t const error_code,  // read-only
    char const* const error_text,  // read-only
    void* const arg);

/*
 * ICE gatherer local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (*rawrtc_ice_gatherer_local_candidate_handler)(
    struct rawrtc_ice_candidate* const candidate,
    char const* const url,  // read-only
    void* const arg);

/*
 * Create a new ICE gatherer.
 * `*gathererp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gatherer_create(
    struct rawrtc_ice_gatherer** const gathererp,  // de-referenced
    struct rawrtc_ice_gather_options* const options,  // referenced
    rawrtc_ice_gatherer_state_change_handler const state_change_handler,  // nullable
    rawrtc_ice_gatherer_error_handler const error_handler,  // nullable
    rawrtc_ice_gatherer_local_candidate_handler const local_candidate_handler,  // nullable
    void* const arg  // nullable
);

/*
 * Close the ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_close(struct rawrtc_ice_gatherer* const gatherer);

/*
 * Start gathering using an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_gather(
    struct rawrtc_ice_gatherer* const gatherer,
    struct rawrtc_ice_gather_options* const options  // referenced, nullable
);

/*
 * TODO (from RTCIceGatherer interface)
 * rawrtc_ice_gatherer_get_component
 */

/*
 * Get the current state of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_state(
    enum rawrtc_ice_gatherer_state* const statep,  // de-referenced
    struct rawrtc_ice_gatherer* const gatherer);

/*
 * Get local ICE parameters of an ICE gatherer.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_parameters(
    struct rawrtc_ice_parameters** const parametersp,  // de-referenced
    struct rawrtc_ice_gatherer* const gatherer);

/*
 * Get local ICE candidates of an ICE gatherer.
 * `*candidatesp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_candidates(
    struct rawrtc_ice_candidates** const candidatesp,  // de-referenced
    struct rawrtc_ice_gatherer* const gatherer);

/*
 * TODO (from RTCIceGatherer interface)
 * rawrtc_ice_gatherer_create_associated_gatherer (unsupported)
 * rawrtc_ice_gatherer_set_state_change_handler
 * rawrtc_ice_gatherer_set_error_handler
 * rawrtc_ice_gatherer_set_local_candidate_handler
 */

/*
 * Get the corresponding name for an ICE gatherer state.
 */
char const* rawrtc_ice_gatherer_state_to_name(enum rawrtc_ice_gatherer_state const state);
