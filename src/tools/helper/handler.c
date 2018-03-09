#include <string.h> // strlen
#include <rawrtc.h>
#include "common.h"
#include "utils.h"
#include "handler.h"

#define DEBUG_MODULE "helper-handler"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Print the ICE gatherer's state.
 */
void default_ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_gatherer_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer state: %s\n", client->name, state_name);
}

/*
 * Print the ICE gatherer's error event.
 */
void default_ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) candidate; (void) error_code; (void) arg;
    DEBUG_NOTICE("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

/*
 * Print the newly gathered local candidate.
 */
void default_ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) arg;
    print_ice_candidate(candidate, url, NULL, client);
}

/*
 * Print the ICE transport's state.
 */
void default_ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_transport_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE transport state: %s\n", client->name, state_name);
}

/*
 * Print the ICE candidate pair change event.
 */
void default_ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) local; (void) remote;
    DEBUG_PRINTF("(%s) ICE transport candidate pair change\n", client->name);
}

/*
 * Print the DTLS transport's state.
 */
void default_dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_dtls_transport_state_to_name(state);
    DEBUG_PRINTF("(%s) DTLS transport state change: %s\n", client->name, state_name);
}

/*
 * Print the DTLS transport's error event.
 */
void default_dtls_transport_error_handler(
        // TODO: error.message (probably from OpenSSL)
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    // TODO: Print error message
    DEBUG_WARNING("(%s) DTLS transport error: %s\n", client->name, "???");
}

/*
 * Print the SCTP transport's state.
 */
void default_sctp_transport_state_change_handler(
        enum rawrtc_sctp_transport_state const state,
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_sctp_transport_state_to_name(state);
    DEBUG_PRINTF("(%s) SCTP transport state change: %s\n", client->name, state_name);
}

/*
 * Print the newly created data channel's parameter.
 */
void default_data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    struct rawrtc_data_channel_parameters* parameters;
    enum rawrtc_code const ignore[] = {RAWRTC_CODE_NO_VALUE};
    char* label = NULL;

    // Get data channel label and protocol
    EOE(rawrtc_data_channel_get_parameters(&parameters, channel));
    EOEIGN(rawrtc_data_channel_parameters_get_label(&label, parameters), ignore);
    DEBUG_INFO("(%s) New data channel instance: %s\n", client->name, label ? label : "n/a");
    mem_deref(label);
    mem_deref(parameters);
}

/*
 * Print the data channel open event.
 */
void default_data_channel_open_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel open: %s\n", client->name, channel->label);
}

/*
 * Print the data channel buffered amount low event.
 */
void default_data_channel_buffered_amount_low_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel buffered amount low: %s\n", client->name, channel->label);
}

/*
 * Print the data channel error event.
 */
void default_data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_WARNING("(%s) Data channel error: %s\n", client->name, channel->label);
}

/*
 * Print the data channel close event.
 */
void default_data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel closed: %s\n", client->name, channel->label);
}

char const* const separator = ", ";

int debug_data_channel_message_flags(
        struct re_printf* const pf,
        enum rawrtc_data_channel_message_flag const flags
) {
    int err = 0;
    char const* prefix = "";

    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_ABORTED) {
        err |= re_hprintf(pf, "%saborted", prefix);
        prefix = separator;
    }
    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_COMPLETE) {
        err |= re_hprintf(pf, "%scomplete", prefix);
        prefix = separator;
    }
    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_STRING) {
        err |= re_hprintf(pf, "%sstring", prefix);
        prefix = separator;
    }
    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_BINARY) {
        err |= re_hprintf(pf, "%sbinary", prefix);
    }

    return err;
}

/*
 * Print the data channel's received message's size.
 */
void default_data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_helper* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Incoming message for data channel %s: %zu bytes; flags=(%H)\n",
                 client->name, channel->label, mbuf_get_left(buffer),
                 debug_data_channel_message_flags, flags);
}

/*
 * Print negotiation needed (duh!)
 */
void default_negotiation_needed_handler(
        void* const arg
) {
    struct client* const client = arg;
    DEBUG_PRINTF("(%s) Negotiation needed\n", client->name);
}

/*
 * Print the peer connection's state.
 */
void default_peer_connection_state_change_handler(
        enum rawrtc_peer_connection_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_peer_connection_state_to_name(state);
    DEBUG_PRINTF("(%s) Peer connection state change: %s\n", client->name, state_name);
}

/*
 * Print the newly gathered local candidate (peer connection variant).
 */
void default_peer_connection_local_candidate_handler(
        struct rawrtc_peer_connection_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct client* const client = arg;
    struct rawrtc_ice_candidate* ortc_candidate = NULL;

    // Get underlying ORTC ICE candidate (if any)
    if (candidate) {
        EOE(rawrtc_peer_connection_ice_candidate_get_ortc_candidate(&ortc_candidate, candidate));
    }

    // Print local candidate
    print_ice_candidate(ortc_candidate, url, candidate, client);
    mem_deref(ortc_candidate);
}

/*
 * Print the peer connections local candidate error event.
 */
void default_peer_connection_local_candidate_error_handler(
        struct rawrtc_peer_connection_ice_candidate* const candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) candidate; (void) error_code; (void) arg;
    DEBUG_NOTICE("(%s) ICE candidate error, URL: %s, reason: %s\n", client->name, url, error_text);
}

/*
 * Print the signaling state.
 */
void default_signaling_state_change_handler(
        enum rawrtc_signaling_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_signaling_state_to_name(state);
    DEBUG_PRINTF("(%s) Signaling state change: %s\n", client->name, state_name);
};

/*
 * Stop the main loop.
 */
void default_signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

/*
 * FD-listener that stops the main loop in case the input buffer
 * contains a line feed or a carriage return.
 */
void stop_on_return_handler(
        int flags,
        void* arg
) {
    char buffer[128];
    size_t length;
    (void) flags;
    (void) arg;

    // Get message from stdin
    if (!fgets((char*) buffer, 128, stdin)) {
        EOR(errno);
    }
    length = strlen(buffer);

    // Exit?
    if (length > 0 && length < 3 && (buffer[0] == '\n' || buffer[0] == '\r')) {
        // Stop main loop
        DEBUG_INFO("Exiting\n");
        re_cancel();
    }
}
