#pragma once
#include "ice_gatherer.h"
#include "ice_transport.h"
#include "peer_connection_state.h"
#include <rawrtc/peer_connection_configuration.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/data_channel.h>
#include <rawrtcdc/data_channel_parameters.h>
#include <re.h>

// Dependencies
struct rawrtc_peer_connection_description;
struct rawrtc_peer_connection_ice_candidate;

/*
 * Peer connection.
 */
struct rawrtc_peer_connection;

/*
 * Peer connection state change handler.
 */
typedef void (*rawrtc_peer_connection_state_change_handler)(
    enum rawrtc_peer_connection_state const state,  // read-only
    void* const arg);

/*
 * Negotiation needed handler.
 */
typedef void (*rawrtc_negotiation_needed_handler)(void* const arg);

/*
 * Peer connection ICE local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (*rawrtc_peer_connection_local_candidate_handler)(
    struct rawrtc_peer_connection_ice_candidate* const candidate,
    char const* const url,  // read-only
    void* const arg);

/*
 * Peer connection ICE local candidate error handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (*rawrtc_peer_connection_local_candidate_error_handler)(
    struct rawrtc_peer_connection_ice_candidate* const candidate,  // read-only, nullable
    char const* const url,  // read-only
    uint16_t const error_code,  // read-only
    char const* const error_text,  // read-only
    void* const arg);

/*
 * Signaling state handler.
 */
typedef void (*rawrtc_signaling_state_change_handler)(
    enum rawrtc_signaling_state const state,  // read-only
    void* const arg);

/*
 * Create a new peer connection.
 * `*connectionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create(
    struct rawrtc_peer_connection** const connectionp,  // de-referenced
    struct rawrtc_peer_connection_configuration* configuration,  // referenced
    rawrtc_negotiation_needed_handler const negotiation_needed_handler,  // nullable
    rawrtc_peer_connection_local_candidate_handler const local_candidate_handler,  // nullable
    rawrtc_peer_connection_local_candidate_error_handler const
        local_candidate_error_handler,  // nullable
    rawrtc_signaling_state_change_handler const signaling_state_change_handler,  // nullable
    rawrtc_ice_transport_state_change_handler const
        ice_connection_state_change_handler,  // nullable
    rawrtc_ice_gatherer_state_change_handler const ice_gathering_state_change_handler,  // nullable
    rawrtc_peer_connection_state_change_handler const connection_state_change_handler,  // nullable
    rawrtc_data_channel_handler const data_channel_handler,  // nullable
    void* const arg  // nullable
);

/*
 * Close the peer connection. This will stop all underlying transports
 * and results in a final 'closed' state.
 */
enum rawrtc_code rawrtc_peer_connection_close(struct rawrtc_peer_connection* const connection);

/*
 * Create an offer.
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create_offer(
    struct rawrtc_peer_connection_description** const descriptionp,  // de-referenced
    struct rawrtc_peer_connection* const connection,
    bool const ice_restart);

/*
 * Create an answer.
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create_answer(
    struct rawrtc_peer_connection_description** const descriptionp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set and apply the local description.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_description(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_description* const description  // referenced
);

/*
 * Get local description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no local description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_description(
    struct rawrtc_peer_connection_description** const descriptionp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set and apply the remote description.
 */
enum rawrtc_code rawrtc_peer_connection_set_remote_description(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_description* const description  // referenced
);

/*
 * Get remote description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_get_remote_description(
    struct rawrtc_peer_connection_description** const descriptionp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Add an ICE candidate to the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_add_ice_candidate(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_ice_candidate* const candidate);

/*
 * Get the current signalling state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state(
    enum rawrtc_signaling_state* const statep,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Get the current ICE gathering state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state(
    enum rawrtc_ice_gatherer_state* const statep,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Get the current ICE connection state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state(
    enum rawrtc_ice_transport_state* const statep,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Get the current (peer) connection state of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state(
    enum rawrtc_peer_connection_state* const statep,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Get indication whether the remote peer accepts trickled ICE
 * candidates.
 *
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_can_trickle_ice_candidates(
    bool* const can_trickle_ice_candidatesp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Create a data channel on a peer connection.
 * `*channelp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create_data_channel(
    struct rawrtc_data_channel** const channelp,  // de-referenced
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_data_channel_parameters* const parameters,  // referenced
    rawrtc_data_channel_open_handler const open_handler,  // nullable
    rawrtc_data_channel_buffered_amount_low_handler const buffered_amount_low_handler,  // nullable
    rawrtc_data_channel_error_handler const error_handler,  // nullable
    rawrtc_data_channel_close_handler const close_handler,  // nullable
    rawrtc_data_channel_message_handler const message_handler,  // nullable
    void* const arg  // nullable
);

/*
 * Unset the handler argument and all handlers of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_unset_handlers(
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's negotiation needed handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_negotiation_needed_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_negotiation_needed_handler const negotiation_needed_handler  // nullable
);

/*
 * Get the peer connection's negotiation needed handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_negotiation_needed_handler(
    rawrtc_negotiation_needed_handler* const negotiation_needed_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's ICE local candidate handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_local_candidate_handler const local_candidate_handler  // nullable
);

/*
 * Get the peer connection's ICE local candidate handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_handler(
    rawrtc_peer_connection_local_candidate_handler* const
        local_candidate_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's ICE local candidate error handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_error_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_local_candidate_error_handler const
        local_candidate_error_handler  // nullable
);

/*
 * Get the peer connection's ICE local candidate error handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_error_handler(
    rawrtc_peer_connection_local_candidate_error_handler* const
        local_candidate_error_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's signaling state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_signaling_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_signaling_state_change_handler const signaling_state_change_handler  // nullable
);

/*
 * Get the peer connection's signaling state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state_change_handler(
    rawrtc_signaling_state_change_handler* const signaling_state_change_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's ice connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_connection_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_ice_transport_state_change_handler const ice_connection_state_change_handler  // nullable
);

/*
 * Get the peer connection's ice connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state_change_handler(
    rawrtc_ice_transport_state_change_handler* const
        ice_connection_state_change_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's ice gathering state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_gathering_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_ice_gatherer_state_change_handler const ice_gathering_state_change_handler  // nullable
);

/*
 * Get the peer connection's ice gathering state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state_change_handler(
    rawrtc_ice_gatherer_state_change_handler* const
        ice_gathering_state_change_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's (peer) connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_connection_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_state_change_handler const connection_state_change_handler  // nullable
);

/*
 * Get the peer connection's (peer) connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state_change_handler(
    rawrtc_peer_connection_state_change_handler* const
        connection_state_change_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);

/*
 * Set the peer connection's data channel handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_data_channel_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_data_channel_handler const data_channel_handler  // nullable
);

/*
 * Get the peer connection's data channel handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_data_channel_handler(
    rawrtc_data_channel_handler* const data_channel_handlerp,  // de-referenced
    struct rawrtc_peer_connection* const connection);
