#pragma once
// TODO: Move this section into meson build
#define ANYRTC_DEBUG 1

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netinet/in.h>

#define ZF_LOG_LIBRARY_PREFIX anyrtc_
#ifdef ANYRTC_DEBUG
    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_DEBUG
#else
    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_WARN
#endif
#include <zf_log.h>

#include <re.h>
#include <rew.h>

enum anyrtc_code {
    ANYRTC_CODE_UNKNOWN_ERROR = -2,
    ANYRTC_CODE_NOT_IMPLEMENTED = -1,
    ANYRTC_CODE_SUCCESS = 0,
    ANYRTC_CODE_INITIALISE_FAIL,
    ANYRTC_CODE_INVALID_ARGUMENT,
    ANYRTC_CODE_NO_MEMORY,
    ANYRTC_CODE_INVALID_STATE,
    ANYRTC_CODE_UNSUPPORTED_PROTOCOL,
};

/*
 * ICE gather policy.
 */
enum anyrtc_ice_gather_policy {
    ANYRTC_ICE_GATHER_ALL,
    ANYRTC_ICE_GATHER_NOHOST,
    ANYRTC_ICE_GATHER_RELAY,
};

/*
 * ICE credential type
 */
enum anyrtc_ice_credential_type {
    ANYRTC_ICE_CREDENTIAL_NONE,
    ANYRTC_ICE_CREDENTIAL_PASSWORD,
    ANYRTC_ICE_CREDENTIAL_TOKEN,
};

/*
 * ICE gatherer state.
 */
enum anyrtc_ice_gatherer_state {
    ANYRTC_ICE_GATHERER_NEW,
    ANYRTC_ICE_GATHERER_GATHERING,
    ANYRTC_ICE_GATHERER_COMPLETE,
    ANYRTC_ICE_GATHERER_CLOSED,
};

/*
 * ICE component.
 * Note: For now, only "RTP" will be supported/returned as we do not support
 * RTP or RTCP.
 */
enum anyrtc_ice_component {
    ANYRTC_ICE_COMPONENT_RTP,
    ANYRTC_ICE_COMPONENT_RTCP,
};

/*
 * Current role of the ICE transport.
 */
enum anyrtc_ice_role {
    ANYRTC_ICE_ROLE_CONTROLLING,
    ANYRTC_ICE_ROLE_CONTROLLED,
};

/*
 * ICE transport state.
 */
 enum anyrtc_ice_transport_state {
     ANYRTC_ICE_TRANSPORT_NEW,
     ANYRTC_ICE_TRANSPORT_CHECKING,
     ANYRTC_ICE_TRANSPORT_CONNECTED,
     ANYRTC_ICE_TRANSPORT_COMPLETED,
     ANYRTC_ICE_TRANSPORT_DISCONNECTED,
     ANYRTC_ICE_TRANSPORT_FAILED,
     ANYRTC_ICE_TRANSPORT_CLOSED,
 };

/*
 * DTLS transport state.
 */
enum anyrtc_dtls_transport_state {
    ANYRTC_DTLS_TRANSPORT_STATE_NEW,
    ANYRTC_DTLS_TRANSPORT_STATE_CONNECTING,
    ANYRTC_DTLS_TRANSPORT_STATE_CONNECTED,
    ANYRTC_DTLS_TRANSPORT_STATE_CLOSED,
    ANYRTC_DTLS_TRANSPORT_STATE_FAILED
};

/*
 * Data channel SCTP payload protocol identifier.
 */ 
enum anyrtc_data_channel_sctp_ppid {
    ANYRTC_DATA_CHANNEL_SCTP_PPID_CONTROL = 50,
    ANYRTC_DATA_CHANNEL_SCTP_PPID_DOMSTRING = 51,
    ANYRTC_DATA_CHANNEL_SCTP_PPID_BINARY = 52,
};

/*
 * SCTP transport state.
 */
enum anyrtc_sctp_transport_state {
    ANYRTC_SCTP_TRANSPORT_STATE_NEW,
    ANYRTC_SCTP_TRANSPORT_STATE_CONNECTING,
    ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED,
    ANYRTC_SCTP_TRANSPORT_STATE_CLOSED
};

/*
 * ICE protocol
 */
enum anyrtc_ice_protocol {
    ANYRTC_ICE_PROTOCOL_UDP = IPPROTO_UDP,
    ANYRTC_ICE_PROTOCOL_TCP = IPPROTO_TCP
};



/*
 * Struct prototypes.
 * TODO: Remove
 */
struct anyrtc_ice_candidate;
struct anyrtc_data_channel;
struct anyrtc_ice_parameters;
struct anyrtc_dtls_transport;
struct anyrtc_dtls_parameters;
struct anyrtc_data_channel_parameters;
struct anyrtc_data_transport;
struct anyrtc_sctp_transport;
struct anyrtc_sctp_capabilities;



/*
 * ICE gatherer state change handler.
 */
typedef void (anyrtc_ice_gatherer_state_change_handler)(
    enum anyrtc_ice_gatherer_state const state, // read-only
    void* const arg
);
 
/*
 * ICE gatherer error handler.
 */
typedef void (anyrtc_ice_gatherer_error_handler)(
    struct anyrtc_ice_candidate* const host_candidate, // read-only, nullable
    char const * const url, // read-only
    uint16_t const error_code, // read-only
    char const * const error_text, // read-only
    void* const arg
);

/*
 * Ice gatherer local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 */
typedef void (anyrtc_ice_gatherer_local_candidate_handler)(
    struct anyrtc_ice_candidate* const candidate, // read-only
    char const * const url, // read-only
    void* const arg
);

/*
 * ICE transport state change handler.
 */
typedef void (anyrtc_ice_transport_state_change_handler)(
    enum anyrtc_ice_transport_state const state, // read-only
    void* const arg
);

/*
 * ICE transport pair change handler.
 */
typedef void (anyrtc_ice_transport_candidate_pair_change_handler)(
    struct anyrtc_ice_candidate* const local, // read-only
    struct anyrtc_ice_candidate* const remote, // read-only
    void* const arg
);

/*
 * DTLS transport state change handler.
 */
typedef void (anyrtc_dtls_transport_state_change_handler)(
    enum anyrtc_dtls_transport_state const state, // read-only
    void* const arg
);

/*
 * DTLS transport error handler.
 */
typedef void (anyrtc_dtls_transport_error_handler)(
    /* TODO: error.message (probably from OpenSSL) */
    void* const arg
);

/*
 * Data channel open handler.
 */
typedef void (anyrtc_data_channel_open_handler)(
    void* const arg
);

/*
 * Data channel buffered amount low handler.
 */
typedef void (anyrtc_data_channel_buffered_amount_low_handler)(
    void* const arg
);

/*
 * Data channel error handler.
 */
typedef void (anyrtc_data_channel_error_handler)(
    /* TODO */
    void* const arg
);

/*
 * Data channel close handler.
 */
typedef void (anyrtc_data_channel_close_handler)(
    void* const arg
);

/*
 * Data channel message handler.
 */
typedef void (anyrtc_data_channel_message_handler)(
    enum anyrtc_data_channel_sctp_ppid const,
    uint8_t const * const data, // read-only
    uint32_t const size,
    void* const arg
);

/*
 * SCTP transport data channel handler.
 */
typedef void (anyrtc_sctp_transport_data_channel_handler)(
    struct anyrtc_data_channel* const, // read-only, MUST be referenced when used
    void* const arg
);

/*
 * SCTP transport state change handler.
 */
typedef void (anyrtc_sctp_transport_state_change_handler)(
    enum anyrtc_sctp_transport_state const,
    void* const arg
);



/*
 * ICE gather options.
 * TODO: private
 */
struct anyrtc_ice_gather_options {
    enum anyrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
};

/*
 * ICE server.
 * TODO: private
 */
struct anyrtc_ice_server {
    struct le le;
    struct list urls; // deep-copied
    char* username; // copied
    char* credential; // copied
    enum anyrtc_ice_credential_type credential_type;
};

/*
 * ICE server URL. (list element)
 * TODO: private
 */
struct anyrtc_ice_server_url {
    struct le le;
    char* url;
};

/*
 * ICE candidate.
 * TODO: private
 */
struct anyrtc_ice_candidate {
    struct le le;
    uint32_t key;
    char foundation[32];
    uint32_t priority;
    struct sa address;
    enum anyrtc_ice_protocol protocol;
    enum ice_cand_type type;
    enum ice_tcptype tcp_type;
    struct sa related_address; // zero if host candidate
};

/*
 * ICE gatherer.
 * TODO: private
 */
struct anyrtc_ice_gatherer {
    enum anyrtc_ice_gatherer_state state;
    struct anyrtc_ice_gather_options* options; // referenced
    anyrtc_ice_gatherer_state_change_handler* state_change_handler; // nullable
    anyrtc_ice_gatherer_error_handler* error_handler; // nullable
    anyrtc_ice_gatherer_local_candidate_handler* local_candidate_handler; // nullable
    void* arg; // nullable
    char ice_username_fragment[9];
    char ice_password[33];
    struct trice* ice;
    struct trice_conf ice_config;
};

/*
 * ICE transport.
 * TODO: private
 */
struct anyrtc_ice_transport {
    struct anyrtc_ice_gatherer* gatherer; // referenced
    enum anyrtc_ice_role role;
    enum anyrtc_ice_transport_state state;
};

/*
 * Layers.
 * TODO: private
 */
enum {
    ANYRTC_LAYER_SCTP = 3,
    ANYRTC_LAYER_DCEP = 2,
    ANYRTC_LAYER_DTLS = 1,
    ANYRTC_LAYER_ICE = 0,
    ANYRTC_LAYER_STUN = -10,
    ANYRTC_LAYER_TURN = -10
};



/*
 * Initialise anyrtc. Must be called before making a call to any other
 * function
 */
enum anyrtc_code anyrtc_init();

/*
 * Close anyrtc and free up all resources.
 */
enum anyrtc_code anyrtc_close();

/*
 * Create a new ICE gather options.
 */
enum anyrtc_code anyrtc_ice_gather_options_create(
    struct anyrtc_ice_gather_options** const optionsp, // de-referenced
    enum anyrtc_ice_gather_policy const gather_policy
);

/*
 * TODO
 * anyrtc_ice_server_list_*
 */

/*
 * Add an ICE server to the gather options.
 */
enum anyrtc_code anyrtc_ice_gather_options_add_server(
    struct anyrtc_ice_gather_options* const options,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum anyrtc_ice_credential_type const credential_type
);

/*
 * TODO (from RTCIceServer interface)
 * anyrtc_ice_server_set_username
 * anyrtc_ice_server_set_credential
 * anyrtc_ice_server_set_credential_type
 */

/*
 * Get the corresponding name for an ICE gatherer state.
 */
char const * const anyrtc_ice_gatherer_state_to_name(
    enum anyrtc_ice_gatherer_state state
);

 /*
  * Create a new ICE gatherer.
  */
enum anyrtc_code anyrtc_ice_gatherer_create(
    struct anyrtc_ice_gatherer** const gathererp, // de-referenced
    struct anyrtc_ice_gather_options* const options, // referenced
    anyrtc_ice_gatherer_state_change_handler* const state_change_handler, // nullable
    anyrtc_ice_gatherer_error_handler* const error_handler, // nullable
    anyrtc_ice_gatherer_local_candidate_handler* const local_candidate_handler, // nullable
    void* const arg // nullable
);

/*
 * Close the ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_close(
    struct anyrtc_ice_gatherer* const gatherer
);

/*
 * Start gathering using an ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_gather(
    struct anyrtc_ice_gatherer* const gatherer,
    struct anyrtc_ice_gather_options* const options // referenced, nullable
);

/*
 * TODO (from RTCIceGatherer interface)
 * anyrtc_ice_gatherer_get_component
 * anyrtc_ice_gatherer_get_state
 * anyrtc_ice_gatherer_get_local_parameters
 * anyrtc_ice_gatherer_get_local_candidates
 * anyrtc_ice_gatherer_create_associated_gatherer (unsupported)
 * anyrtc_ice_gatherer_set_state_change_handler
 * anyrtc_ice_gatherer_set_error_handler
 * anyrtc_ice_gatherer_set_local_candidate_handler
 */
 
/*
 * Create a new ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_create(
    struct anyrtc_ice_transport** const transport, // de-referenced
    struct anyrtc_ice_gatherer* const gatherer, // referenced, nullable
    anyrtc_ice_transport_state_change_handler* const state_change_handler, // nullable
    anyrtc_ice_transport_candidate_pair_change_handler* const candidate_pair_change_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_start(
    struct anyrtc_ice_transport* const transport,
    struct anyrtc_ice_gatherer* const gatherer, // referenced
    struct anyrtc_ice_parameters const * const remote_parameters, // copied
    enum anyrtc_ice_role const role
);

/*
 * Stop and close the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_stop(
    struct anyrtc_ice_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * anyrtc_ice_transport_get_ice_gatherer
 * anyrtc_ice_transport_get_role
 * anyrtc_ice_transport_get_component
 * anyrtc_ice_transport_get_state
 * anyrtc_ice_transport_get_remote_candidates
 * anyrtc_ice_transport_get_selected_candidate_pair
 * anyrtc_ice_transport_get_remote_parameters
 * anyrtc_ice_transport_create_associated_transport (unsupported)
 * anyrtc_ice_transport_set_state_change_handler
 * anyrtc_ice_transport_set_candidate_pair_change_handler
 */
  
/*
 * Create a new DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_create(
    struct anyrtc_dtls_transport** const transport, // de-referenced
    struct anyrtc_ice_transport* const ice_transport, // referenced
    struct list const * const certificates, // deep-copied
    anyrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
    anyrtc_dtls_transport_error_handler* const error_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_start(
    struct anyrtc_dtls_transport* const transport,
    struct anyrtc_dtls_parameters const * const remote_parameters // copied
);

/*
 * Stop and close the DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_stop(
    struct anyrtc_dtls_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * anyrtc_certificate_list_*
 * anyrtc_dtls_transport_get_certificates
 * anyrtc_dtls_transport_get_transport
 * anyrtc_dtls_transport_get_state
 * anyrtc_dtls_transport_get_local_parameters
 * anyrtc_dtls_transport_get_remote_parameters
 * anyrtc_dtls_transport_get_remote_certificates
 * anyrtc_dtls_transport_set_state_change_handler
 * anyrtc_dtls_transport_set_error_handler
 */

/*
 * Create a data channel.
 */
enum anyrtc_code anyrtc_data_channel_create(
    struct anyrtc_data_channel** const channel, // de-referenced
    struct anyrtc_data_transport* const transport, // referenced
    struct anyrtc_data_channel_parameters const * const parameters, // copied
    anyrtc_data_channel_open_handler* const open_handler, // nullable
    anyrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    anyrtc_data_channel_error_handler* const error_handler, // nullable
    anyrtc_data_channel_close_handler* const close_handler, // nullable
    anyrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg // nullable
);

/*
 * Close the data channel.
 */
enum anyrtc_code anyrtc_data_channel_close(
    struct anyrtc_data_channel* const channel
);

/*
 * Send data via the data channel.
 */
enum anyrtc_code anyrtc_data_channel_send(
    struct anyrtc_data_channel* const channel,
    enum anyrtc_data_channel_sctp_ppid const,
    uint8_t const * const data,
    uint32_t const size
);

/*
 * TODO (from RTCDataChannel interface)
 * anyrtc_data_channel_get_transport
 * anyrtc_data_channel_get_ready_state
 * anyrtc_data_channel_get_buffered_amount
 * anyrtc_data_channel_get_buffered_amount_low_threshold
 * anyrtc_data_channel_set_buffered_amount_low_threshold
 * anyrtc_data_channel_get_parameters
 * anyrtc_data_channel_set_open_handler
 * anyrtc_data_channel_set_buffered_amount_low_handler
 * anyrtc_data_channel_set_error_handler
 * anyrtc_data_channel_set_close_handler
 * anyrtc_data_channel_set_message_handler
 */

/*
 * Create an SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_create(
    struct anyrtc_sctp_transport** const transport, // de-referenced
    struct anyrtc_dtls_transport* const dtls_transport, // referenced
    uint16_t const port, // zeroable
    anyrtc_sctp_transport_data_channel_handler* const data_channel_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_start(
    struct anyrtc_sctp_transport* const transport,
    struct anyrtc_sctp_capabilities const * const remote_capabilities // copied
);

/*
 * Stop and close the SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_stop(
    struct anyrtc_sctp_transport* const transport
);

/*
 * TODO (from RTCSctpTransport interface)
 * anyrtc_sctp_transport_get_transport
 * anyrtc_sctp_transport_get_state
 * anyrtc_sctp_transport_get_port
 * anyrtc_sctp_transport_get_capabilities
 * anyrtc_sctp_transport_set_data_channel_handler
 */



/*
 * Translate an re error to an anyrtc code.
 */
enum anyrtc_code anyrtc_code_re_translate(
    int code
);
