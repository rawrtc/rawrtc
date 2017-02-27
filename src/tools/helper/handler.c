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
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

/*
 * Print the newly gatherered local candidate.
 */
void default_ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    (void) candidate; (void) arg;

    if (candidate) {
        enum rawrtc_code const ignore[] = {RAWRTC_CODE_NO_VALUE};
        enum rawrtc_code error;
        char* foundation;
        enum rawrtc_ice_protocol protocol;
        uint32_t priority;
        char* ip;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type;
        char const* tcp_type_str = "N/A";
        char* related_address = NULL;
        uint16_t related_port = 0;

        // Get candidate information
        EOE(rawrtc_ice_candidate_get_foundation(&foundation, candidate));
        EOE(rawrtc_ice_candidate_get_protocol(&protocol, candidate));
        EOE(rawrtc_ice_candidate_get_priority(&priority, candidate));
        EOE(rawrtc_ice_candidate_get_ip(&ip, candidate));
        EOE(rawrtc_ice_candidate_get_port(&port, candidate));
        EOE(rawrtc_ice_candidate_get_type(&type, candidate));
        error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                tcp_type_str = rawrtc_ice_tcp_candidate_type_to_str(tcp_type);
                break;
            case RAWRTC_CODE_NO_VALUE:
                break;
            default:
                EOE(error);
                break;
        }
        EOEIGN(rawrtc_ice_candidate_get_related_address(&related_address, candidate), ignore);
        EOEIGN(rawrtc_ice_candidate_get_related_port(&related_port, candidate), ignore);

        // Print candidate
        DEBUG_PRINTF("(%s) ICE gatherer local candidate: foundation=%s, protocol=%s, priority=%"
                     PRIu32", ip=%s, port=%"PRIu16", type=%s, tcp-type=%s, related-address=%s, "
                     "related-port=%"PRIu16"; URL: %s\n",
                     client->name, foundation, rawrtc_ice_protocol_to_str(protocol), priority, ip, port,
                     rawrtc_ice_candidate_type_to_str(type), tcp_type_str,
                     related_address ? related_address : "N/A", related_port, url ? url : "N/A");

        // Unreference
        mem_deref(related_address);
        mem_deref(ip);
        mem_deref(foundation);
    } else {
        DEBUG_PRINTF("(%s) ICE gatherer last local candidate\n", client->name);
    }
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
        /* TODO: error.message (probably from OpenSSL) */
        void* const arg // will be casted to `struct client*`
) {
    struct client* const client = arg;
    // TODO: Print error message
    DEBUG_PRINTF("(%s) DTLS transport error: %s\n", client->name, "???");
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
    DEBUG_INFO("(%s) New data channel instance: %s\n", client->name, label ? label : "N/A");
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
    DEBUG_PRINTF("(%s) Data channel error: %s\n", client->name, channel->label);
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
    (void) flags;
    DEBUG_PRINTF("(%s) Incoming message for data channel %s: %"PRIu32" bytes\n",
                 client->name, channel->label, mbuf_get_left(buffer));
}

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
