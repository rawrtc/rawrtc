#pragma once
#include <rawrtc.h>
#include "common.h"

/*
 * Print the ICE gatherer's state.
 */
void default_ice_gatherer_state_change_handler(
    enum rawrtc_ice_gatherer_state const state, // read-only
    void* const arg
);

/*
 * Print the ICE gatherer's error event.
 */
void default_ice_gatherer_error_handler(
    struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
    char const * const url, // read-only
    uint16_t const error_code, // read-only
    char const * const error_text, // read-only
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the newly gatherered local candidate.
 * Will print local parameters on stdout in case the client is not
 * used in loopback mode.
 */
void default_ice_gatherer_local_candidate_handler(
    struct rawrtc_ice_candidate* const candidate,
    char const * const url, // read-only
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the ICE transport's state.
 */
void default_ice_transport_state_change_handler(
    enum rawrtc_ice_transport_state const state,
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the ICE candidate pair change event.
 */
void default_ice_transport_candidate_pair_change_handler(
    struct rawrtc_ice_candidate* const local, // read-only
    struct rawrtc_ice_candidate* const remote, // read-only
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the DTLS transport's state.
 */
void default_dtls_transport_state_change_handler(
    enum rawrtc_dtls_transport_state const state, // read-only
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the DTLS transport's error event.
 */
void default_dtls_transport_error_handler(
    /* TODO: error.message (probably from OpenSSL) */
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the SCTP transport's state.
 */
void default_sctp_transport_state_change_handler(
    enum rawrtc_sctp_transport_state const state,
    void* const arg // will be casted to `struct client*`
);

/*
 * Print the newly created data channel's parameter.
 */
void default_data_channel_handler(
    struct rawrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
    void* const arg // will be casted to `struct data_channel_helper*`
);

/*
 * Print the data channel open event.
 */
void default_data_channel_open_handler(
    void* const arg // will be casted to `struct data_channel_helper*`
);

/*
 * Print the data channel buffered amount low event.
 */
void default_data_channel_buffered_amount_low_handler(
    void* const arg // will be casted to `struct data_channel_helper*`
);

/*
 * Print the data channel error event.
 */
void default_data_channel_error_handler(
    void* const arg // will be casted to `struct data_channel_helper*`
);

/*
 * Print the data channel close event.
 */
void default_data_channel_close_handler(
    void* const arg // will be casted to `struct data_channel_helper*`
);

/*
 * Print the data channel's received message's size.
 */
void default_data_channel_message_handler(
    struct mbuf* const buffer,
    enum rawrtc_data_channel_message_flag const flags,
    void* const arg // will be casted to `struct data_channel_helper*`
);

void default_peer_connection_state_change_handler(
    enum rawrtc_peer_connection_state const state, // read-only
    void* const arg // will be casted to `struct client*`
);

/*
 * Stop the main loop.
 */
void default_signal_handler(
    int sig
);

/*
 * FD-listener that stops the main loop in case the input buffer is
 * empty.
 */
void stop_on_return_handler(
    int flags,
    void* arg
);
