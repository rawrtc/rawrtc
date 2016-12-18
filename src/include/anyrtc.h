#pragma once
// TODO: Move this section into meson build
#define ANYRTC_DEBUG 1

#include <inttypes.h> // uint8_t, UINT8_MAX, ...
#include <stdlib.h> // TODO: Why?
#include <stdbool.h> // bool
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP, ...
#include <openssl/evp.h> // EVP_PKEY

//#define ZF_LOG_LIBRARY_PREFIX anyrtc_
//#ifdef ANYRTC_DEBUG
//    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_DEBUG
//#else
//    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_WARN
//#endif
//#include <zf_log.h>

#include <re.h>
#include <rew.h>

/*
 * Return codes.
 */
enum anyrtc_code {
    ANYRTC_CODE_UNKNOWN_ERROR = -2,
    ANYRTC_CODE_NOT_IMPLEMENTED = -1,
    ANYRTC_CODE_SUCCESS = 0,
    ANYRTC_CODE_INITIALISE_FAIL,
    ANYRTC_CODE_INVALID_ARGUMENT,
    ANYRTC_CODE_NO_MEMORY,
    ANYRTC_CODE_INVALID_STATE,
    ANYRTC_CODE_UNSUPPORTED_PROTOCOL,
    ANYRTC_CODE_UNSUPPORTED_ALGORITHM,
    ANYRTC_CODE_NO_VALUE,
    ANYRTC_CODE_NO_SOCKET,
    ANYRTC_CODE_INVALID_CERTIFICATE,
    ANYRTC_CODE_INVALID_FINGERPRINT,
    ANYRTC_CODE_INSUFFICIENT_SPACE,
};

/*
 * Certificate private key types.
 */
enum anyrtc_certificate_key_type {
    ANYRTC_CERTIFICATE_KEY_TYPE_RSA = TLS_KEYTYPE_RSA,
    ANYRTC_CERTIFICATE_KEY_TYPE_EC = TLS_KEYTYPE_EC
};

/*
 * Certificate signing hash algorithms.
 */
enum anyrtc_certificate_sign_algorithm {
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE = 0,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA1 = TLS_FINGERPRINT_SHA1,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256 = TLS_FINGERPRINT_SHA256,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512
};

/*
 * Certificate encoding.
 */
enum anyrtc_certificate_encode {
    ANYRTC_CERTIFICATE_ENCODE_CERTIFICATE,
    ANYRTC_CERTIFICATE_ENCODE_PRIVATE_KEY,
    ANYRTC_CERTIFICATE_ENCODE_BOTH
};

/*
 * ICE candidate type (internal).
 * TODO: Private
 */
enum anyrtc_ice_candidate_storage {
    ANYRTC_ICE_CANDIDATE_STORAGE_RAW,
    ANYRTC_ICE_CANDIDATE_STORAGE_LCAND,
    ANYRTC_ICE_CANDIDATE_STORAGE_RCAND,
};

/*
 * ICE gather policy.
 */
enum anyrtc_ice_gather_policy {
    ANYRTC_ICE_GATHER_ALL,
    ANYRTC_ICE_GATHER_NOHOST,
    ANYRTC_ICE_GATHER_RELAY
};

/*
 * ICE credential type
 */
enum anyrtc_ice_credential_type {
    ANYRTC_ICE_CREDENTIAL_NONE,
    ANYRTC_ICE_CREDENTIAL_PASSWORD,
    ANYRTC_ICE_CREDENTIAL_TOKEN
};

/*
 * ICE gatherer state.
 */
enum anyrtc_ice_gatherer_state {
    ANYRTC_ICE_GATHERER_NEW,
    ANYRTC_ICE_GATHERER_GATHERING,
    ANYRTC_ICE_GATHERER_COMPLETE,
    ANYRTC_ICE_GATHERER_CLOSED
};

/*
 * ICE component.
 * Note: For now, only "RTP" will be supported/returned as we do not support
 * RTP or RTCP.
 */
enum anyrtc_ice_component {
    ANYRTC_ICE_COMPONENT_RTP,
    ANYRTC_ICE_COMPONENT_RTCP
};

/*
 * ICE role.
 */
enum anyrtc_ice_role {
    ANYRTC_ICE_ROLE_UNKNOWN = ROLE_UNKNOWN,
    ANYRTC_ICE_ROLE_CONTROLLING = ROLE_CONTROLLING,
    ANYRTC_ICE_ROLE_CONTROLLED = ROLE_CONTROLLED
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
     ANYRTC_ICE_TRANSPORT_CLOSED
 };

/*
 * DTLS role.
 */
enum anyrtc_dtls_role {
    ANYRTC_DTLS_ROLE_AUTO,
    ANYRTC_DTLS_ROLE_CLIENT,
    ANYRTC_DTLS_ROLE_SERVER
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
 * Data channel types.
 */
enum anyrtc_data_channel_type {
    ANYRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED = 0x00,
    ANYRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED = 0x80,
    ANYRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_RETRANSMIT = 0x01,
    ANYRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_RETRANSMIT = 0x81,
    ANYRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_TIMED = 0x02,
    ANYRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_TIMED = 0x82
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
 * ICE protocol.
 */
enum anyrtc_ice_protocol {
    ANYRTC_ICE_PROTOCOL_UDP = IPPROTO_UDP,
    ANYRTC_ICE_PROTOCOL_TCP = IPPROTO_TCP
};

/*
 * ICE candidate type.
 */
enum anyrtc_ice_candidate_type {
    ANYRTC_ICE_CANDIDATE_TYPE_HOST = ICE_CAND_TYPE_HOST,
    ANYRTC_ICE_CANDIDATE_TYPE_SRFLX = ICE_CAND_TYPE_SRFLX,
    ANYRTC_ICE_CANDIDATE_TYPE_PRFLX = ICE_CAND_TYPE_PRFLX,
    ANYRTC_ICE_CANDIDATE_TYPE_RELAY = ICE_CAND_TYPE_RELAY
};

/*
 * ICE TCP candidate type.
 */
enum anyrtc_ice_tcp_candidate_type {
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE = ICE_TCP_ACTIVE,
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE = ICE_TCP_PASSIVE,
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_SO = ICE_TCP_SO
};

/*
 * Data transport type.
 */
enum anyrtc_data_transport_type {
    ANYRTC_DATA_TRANSPORT_TYPE_SCTP
};



/*
 * Struct prototypes.
 * TODO: Remove
 */
struct anyrtc_ice_candidate;
struct anyrtc_data_channel;
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
 * ICE gatherer local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (anyrtc_ice_gatherer_local_candidate_handler)(
    struct anyrtc_ice_candidate* const candidate,
    char const * const url, // read-only
    void* const arg
);

/*
 * ICE transport state change handler.
 */
typedef void (anyrtc_ice_transport_state_change_handler)(
    enum anyrtc_ice_transport_state const state,
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
    enum anyrtc_dtls_transport_state const state,
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
 * SCTP transport state change handler.
 */
typedef void (anyrtc_sctp_transport_state_change_handler)(
    enum anyrtc_sctp_transport_state const state,
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
 * TODO: Add binary/string flag
 * TODO: ORTC is really unclear about that handler. Consider improving it with a PR.
 */
typedef void (anyrtc_data_channel_message_handler)(
    uint8_t const * const data, // read-only
    uint32_t const size,
    void* const arg
);

/*
 * Data channel streaming message handler.
 */
typedef void (anyrtc_data_channel_streaming_message_handler)(
    // TODO: Specify streaming API handler
);

/*
 * Data channel handler.
 */
typedef void (anyrtc_data_channel_handler)(
    struct anyrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
    void* const arg
);

/*
 * Handle buffered messages.
 * TODO: private
 */
typedef void (anyrtc_message_buffer_handler)(
    struct mbuf* const buffer,
    void* const context,
    void* const arg
);

/*
 * Handle incoming data messages.
 * TODO: Private
 */
typedef void (anyrtc_dtls_transport_receive_handler)(
    struct mbuf* const buffer,
    void* const arg
);



/*
 * Configuration.
 * TODO: Add to a constructor... somewhere
 */
struct anyrtc_config {
    uint32_t pacing_interval;
    bool ipv4_enable;
    bool ipv6_enable;
    bool udp_enable;
    bool tcp_enable;
    enum anyrtc_certificate_sign_algorithm sign_algorithm;
};

/*
 * Message buffer.
 * TODO: private
 */
struct anyrtc_buffered_message {
    struct le le;
    struct mbuf* buffer; // referenced
    void* context; // referenced, nullable
};

/*
 * Local candidate helper.
 * TODO: private
 */
struct anyrtc_candidate_helper {
    struct le le;
    struct ice_lcand* candidate;
    struct udp_helper* helper;
};

/*
 * Certificate options.
 * TODO: private
 */
struct anyrtc_certificate_options {
    enum anyrtc_certificate_key_type key_type;
    char* common_name; // copied
    uint32_t valid_until;
    enum anyrtc_certificate_sign_algorithm sign_algorithm;
    char* named_curve; // nullable, copied, ignored for RSA
    uint_least32_t modulus_length; // ignored for ECC
};

/*
 * Certificate.
 * TODO: private
 */
struct anyrtc_certificate {
    struct le le;
    X509* certificate;
    EVP_PKEY* key;
    enum anyrtc_certificate_key_type key_type;
};

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
 * Raw ICE candidate (pending candidate).
 * TODO: private
 */
struct anyrtc_ice_candidate_raw {
    char* foundation; // copied
    uint32_t priority;
    char* ip; // copied
    enum anyrtc_ice_protocol protocol;
    uint16_t port;
    enum anyrtc_ice_candidate_type type;
    enum anyrtc_ice_tcp_candidate_type tcp_type;
    char* related_address; // copied
    uint16_t related_port;
};

/*
 * ICE candidate.
 * TODO: private
 */
struct anyrtc_ice_candidate {
    enum anyrtc_ice_candidate_storage storage_type;
    union {
        struct anyrtc_ice_candidate_raw* raw_candidate;
        struct ice_lcand* local_candidate;
        struct ice_rcand* remote_candidate;
    } candidate;
};

/*
 * ICE parameters.
 * TODO: private
 */
struct anyrtc_ice_parameters {
    char* username_fragment; // copied
    char* password; // copied
    bool ice_lite;
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
    struct list buffered_messages;
    struct list candidate_helpers; // TODO: Hash list instead?
    char ice_username_fragment[9];
    char ice_password[33];
    struct trice* ice;
    struct trice_conf ice_config;
    struct stun* stun;
    struct stun_conf stun_config;
};

/*
 * ICE transport.
 * TODO: private
 */
struct anyrtc_ice_transport {
    enum anyrtc_ice_transport_state state;
    struct anyrtc_ice_gatherer* gatherer; // referenced
    anyrtc_ice_transport_state_change_handler* state_change_handler; // nullable
    anyrtc_ice_transport_candidate_pair_change_handler* candidate_pair_change_handler; // nullable
    void* arg; // nullable
    struct anyrtc_ice_parameters* remote_parameters; // referenced
    struct anyrtc_dtls_transport* dtls_transport; // referenced, nullable
};

/*
 * DTLS fingerprint.
 * TODO: private
 */
struct anyrtc_dtls_fingerprint {
    struct le le;
    enum anyrtc_certificate_sign_algorithm algorithm;
    char* value; // copied
};

/*
 * DTLS parameters.
 * TODO: private
 */
struct anyrtc_dtls_parameters {
    enum anyrtc_dtls_role role;
    struct anyrtc_dtls_fingerprints* fingerprints;
};

/*
 * DTLS transport.
 * TODO: private
 */
struct anyrtc_dtls_transport {
    enum anyrtc_dtls_transport_state state;
    struct anyrtc_ice_transport* ice_transport; // referenced
    struct list certificates; // deep-copied
    anyrtc_dtls_transport_state_change_handler* state_change_handler; // nullable
    anyrtc_dtls_transport_error_handler* error_handler; // nullable
    void* arg; // nullable
    struct anyrtc_dtls_parameters* remote_parameters; // referenced
    enum anyrtc_dtls_role role;
    bool connection_established;
    struct list buffered_messages_in;
    struct list buffered_messages_out;
    struct list candidate_helpers; // TODO: Hash list instead?
    struct list fingerprints;
    struct tls* context;
    struct dtls_sock* socket;
    struct tls_conn* connection;
    anyrtc_dtls_transport_receive_handler* receive_handler;
    void* receive_handler_arg;
};

/*
 * Redirect transport.
 */
struct anyrtc_redirect_transport {
    struct anyrtc_dtls_transport* dtls_transport; // referenced
    uint16_t local_port;
    uint16_t remote_port;
    struct sa redirect_address;
    struct mbuf* buffer;
    int socket;
};

/*
 * Generic data transport.
 * TODO: private
 */
struct anyrtc_data_transport {
    enum anyrtc_data_transport_type type;
    void* transport;
};

/*
 * Data channel parameters.
 * TODO: private
 */
struct anyrtc_data_channel_parameters {
    char* label; // copied
    enum anyrtc_data_channel_type channel_type;
    uint32_t channel_value; // contains either max_packet_lifetime or max_retransmit
    char* protocol; // copied
    bool negotiated;
    uint16_t id;
};

/*
 * SCTP capabilities.
 * TODO: private
 */
struct anyrtc_sctp_capabilities {
    uint16_t port;
    uint64_t max_message_size;
};

/*
 * SCTP transport.
 * TODO: private
 */
struct anyrtc_sctp_transport {
    enum anyrtc_sctp_transport_state state;
    uint16_t port;
    uint64_t remote_maximum_message_size;
    struct anyrtc_dtls_transport* dtls_transport; // referenced
    anyrtc_data_channel_handler* data_channel_handler; // nullable
    anyrtc_sctp_transport_state_change_handler* state_change_handler; // nullable
    void* arg; // nullable
    struct list buffered_messages;
    FILE* trace_handle;
    struct socket* socket;
};

/*
 * Layers.
 * TODO: private
 */
enum {
    ANYRTC_LAYER_SCTP = 20,
    ANYRTC_LAYER_DTLS_SRTP_STUN = 10,
    ANYRTC_LAYER_ICE = 0,
    ANYRTC_LAYER_STUN = -10,
    ANYRTC_LAYER_TURN = -10
};



/*
 * ICE candidates.
 */
struct anyrtc_ice_candidates {
    size_t n_candidates;
    struct anyrtc_ice_candidate* candidates[];
};

/*
 * DTLS fingerprints
 */
struct anyrtc_dtls_fingerprints {
    size_t n_fingerprints;
    struct anyrtc_dtls_fingerprint* fingerprints[];
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
 * Create certificate options.
 *
 * All arguments but `key_type` are optional. Sane and safe default
 * values will be applied, don't worry!
 *
 * If `common_name` is `NULL` the default common name will be applied.
 * If `valid_until` is `0` the default certificate lifetime will be
 * applied.
 * If the key type is `ECC` and `named_curve` is `NULL`, the default
 * named curve will be used.
 * If the key type is `RSA` and `modulus_length` is `0`, the default
 * amount of bits will be used. The same applies to the
 * `sign_algorithm` if it has been set to `NONE`.
 */
enum anyrtc_code anyrtc_certificate_options_create(
    struct anyrtc_certificate_options** const optionsp, // de-referenced
    enum anyrtc_certificate_key_type const key_type,
    char* common_name, // nullable, copied
    uint32_t valid_until,
    enum anyrtc_certificate_sign_algorithm sign_algorithm,
    char* named_curve, // nullable, copied, ignored for RSA
    uint_least32_t modulus_length // ignored for ECC
);

/*
 * Create and generate a self-signed certificate.
 *
 * Sane and safe default options will be applied if `options` is
 * `NULL`.
 */
enum anyrtc_code anyrtc_certificate_generate(
    struct anyrtc_certificate** const certificatep,
    struct anyrtc_certificate_options* options // nullable
);

/*
 * TODO http://draft.ortc.org/#dom-rtccertificate
 * anyrtc_certificate_from_bytes
 * anyrtc_certificate_get_expires
 * anyrtc_certificate_get_fingerprint
 * anyrtc_certificate_get_algorithm
 */

/*
 * Create an ICE candidate.
 */
enum anyrtc_code anyrtc_ice_candidate_create(
    struct anyrtc_ice_candidate** const candidatep, // de-referenced
    char* const foundation, // copied
    uint32_t const priority,
    char* const ip, // copied
    enum anyrtc_ice_protocol const protocol,
    uint16_t const port,
    enum anyrtc_ice_candidate_type const type,
    enum anyrtc_ice_tcp_candidate_type const tcp_type,
    char* const related_address, // copied, nullable
    uint16_t const related_port
);

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum anyrtc_code anyrtc_ice_candidate_get_foundation(
    char** const foundationp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's priority.
 */
enum anyrtc_code anyrtc_ice_candidate_get_priority(
    uint32_t* const priorityp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum anyrtc_code anyrtc_ice_candidate_get_ip(
    char** const ipp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's protocol.
 */
enum anyrtc_code anyrtc_ice_candidate_get_protocol(
    enum anyrtc_ice_protocol* const protocolp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's port.
 */
enum anyrtc_code anyrtc_ice_candidate_get_port(
    uint16_t* const portp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's type.
 */
enum anyrtc_code anyrtc_ice_candidate_get_type(
    enum anyrtc_ice_candidate_type* typep, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's TCP type.
 * `*typep` will be set to `NULL` in case the protocol is not TCP.
 */
enum anyrtc_code anyrtc_ice_candidate_get_tcp_type(
    enum anyrtc_ice_tcp_candidate_type* typep, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced or `NULL` in case no related address exists.
 */
enum anyrtc_code anyrtc_ice_candidate_get_related_address(
    char** const related_addressp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port or `0` in case no related address exists.
 */
enum anyrtc_code anyrtc_ice_candidate_get_related_port(
    uint16_t* const related_portp, // de-referenced
    struct anyrtc_ice_candidate* const candidate
);

/*
 * Create a new ICE parameters instance.
 */
enum anyrtc_code anyrtc_ice_parameters_create(
    struct anyrtc_ice_parameters** const parametersp, // de-referenced
    char* const username_fragment, // copied
    char* const password, // copied
    bool const ice_lite
);

/*
 * Get the ICE parameter's username fragment value.
 * `*username_fragmentp` must be unreferenced.
 */
enum anyrtc_code anyrtc_ice_parameters_get_username_fragment(
    char** const username_fragmentp, // de-referenced
    struct anyrtc_ice_parameters* const parameters
);

/*
 * Get the ICE parameter's password value.
 * `*passwordp` must be unreferenced.
 */
enum anyrtc_code anyrtc_ice_parameters_get_password(
    char** const passwordp, // de-referenced
    struct anyrtc_ice_parameters* const parameters
);

/*
 * Get the ICE parameter's ICE lite value.
 */
enum anyrtc_code anyrtc_ice_parameters_get_ice_lite(
    bool* const ice_litep, // de-referenced
    struct anyrtc_ice_parameters* const parameters
);

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
    enum anyrtc_ice_gatherer_state const state
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
 */

/*
 * Get local ICE parameters of an ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_get_local_parameters(
    struct anyrtc_ice_parameters** const parametersp, // de-referenced
    struct anyrtc_ice_gatherer* const gatherer
);

/*
 * Get local ICE candidates of an ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_get_local_candidates(
    struct anyrtc_ice_candidates** const candidatesp, // de-referenced
    struct anyrtc_ice_gatherer* const gatherer
);

/*
 * TODO (from RTCIceGatherer interface)
 * anyrtc_ice_gatherer_create_associated_gatherer (unsupported)
 * anyrtc_ice_gatherer_set_state_change_handler
 * anyrtc_ice_gatherer_set_error_handler
 * anyrtc_ice_gatherer_set_local_candidate_handler
 */

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const anyrtc_ice_transport_state_to_name(
    enum anyrtc_ice_transport_state const state
);

/*
 * Create a new ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_create(
    struct anyrtc_ice_transport** const transportp, // de-referenced
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
    struct anyrtc_ice_parameters* const remote_parameters, // referenced
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
 */

/*
 * Get the current ICE role of the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_get_role(
    enum anyrtc_ice_role* const rolep, // de-referenced
    struct anyrtc_ice_transport* const transport
);

/*
 * TODO
 * anyrtc_ice_transport_get_component
 * anyrtc_ice_transport_get_state
 * anyrtc_ice_transport_get_remote_candidates
 * anyrtc_ice_transport_get_selected_candidate_pair
 * anyrtc_ice_transport_get_remote_parameters
 * anyrtc_ice_transport_create_associated_transport (unsupported)
 */

/*
 * Add a remote candidate ot the ICE transport.
 * Note: 'candidate' must be NULL to inform the transport that the
 * remote site finished gathering.
 */
enum anyrtc_code anyrtc_ice_transport_add_remote_candidate(
    struct anyrtc_ice_transport* const transport,
    struct anyrtc_ice_candidate* candidate // nullable
);

/*
 * Set the remote candidates on the ICE transport overwriting all
 * existing remote candidates.
 */
enum anyrtc_code anyrtc_ice_transport_set_remote_candidates(
    struct anyrtc_ice_transport* const transport,
    struct anyrtc_ice_candidate* const candidates[], // referenced (each item)
    size_t const n_candidates
);

/* TODO (from RTCIceTransport interface)
 * anyrtc_ice_transport_set_state_change_handler
 * anyrtc_ice_transport_set_candidate_pair_change_handler
 */

/*
 * Create a new DTLS fingerprint instance.
 */
enum anyrtc_code anyrtc_dtls_fingerprint_create(
    struct anyrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum anyrtc_certificate_sign_algorithm const algorithm,
    char* const value // copied
);

/*
 * TODO
 * anyrtc_dtls_fingerprint_get_algorithm
 * anyrtc_dtls_fingerprint_get_value
 */

/*
 * Create a new DTLS parameters instance.
 */
enum anyrtc_code anyrtc_dtls_parameters_create(
    struct anyrtc_dtls_parameters** const parametersp, // de-referenced
    enum anyrtc_dtls_role const role,
    struct anyrtc_dtls_fingerprint* const fingerprints[], // referenced (each item)
    size_t const n_fingerprints
);

/*
 * Get the DTLS parameter's role value.
 */
enum anyrtc_code anyrtc_dtls_parameters_get_role(
    enum anyrtc_dtls_role* rolep, // de-referenced
    struct anyrtc_dtls_parameters* const parameters
);

/*
 * Get the DTLS parameter's fingerprint array.
 * `*fingerprintsp` must be unreferenced.
 */
enum anyrtc_code anyrtc_dtls_parameters_get_fingerprints(
    struct anyrtc_dtls_fingerprints** const fingerprintsp, // de-referenced
    struct anyrtc_dtls_parameters* const parameters
);

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum anyrtc_code anyrtc_dtls_parameters_fingerprint_get_sign_algorithm(
    enum anyrtc_certificate_sign_algorithm* const sign_algorithmp, // de-referenced
    struct anyrtc_dtls_fingerprint* const fingerprint
);

/*
 * Get the DTLS certificate's fingerprint value.
 * `*valuep` must be unreferenced.
 */
enum anyrtc_code anyrtc_dtls_parameters_fingerprint_get_value(
    char** const valuep, // de-referenced
    struct anyrtc_dtls_fingerprint* const fingerprint
);

/*
* Get the corresponding name for an ICE transport state.
*/
char const * const anyrtc_dtls_transport_state_to_name(
    enum anyrtc_dtls_transport_state const state
);

/*
 * Create a new DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_create(
    struct anyrtc_dtls_transport** const transportp, // de-referenced
    struct anyrtc_ice_transport* const ice_transport, // referenced
    struct anyrtc_certificate* const certificates[], // copied (each item)
    size_t const n_certificates,
    anyrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
    anyrtc_dtls_transport_error_handler* const error_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_start(
    struct anyrtc_dtls_transport* const transport,
    struct anyrtc_dtls_parameters* const remote_parameters // copied
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
 */

/*
 * Get local DTLS parameters of a transport.
 */
enum anyrtc_code anyrtc_dtls_transport_get_local_parameters(
    struct anyrtc_dtls_parameters** const parametersp, // de-referenced
    struct anyrtc_dtls_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * anyrtc_dtls_transport_get_remote_parameters
 * anyrtc_dtls_transport_get_remote_certificates
 * anyrtc_dtls_transport_set_state_change_handler
 * anyrtc_dtls_transport_set_error_handler
 */

/*
 * Create a redirect transport.
 * `local_port` and `remote_port` may be `0`.
 */
enum anyrtc_code anyrtc_redirect_transport_create(
    struct anyrtc_redirect_transport** const transportp, // de-referenced
    struct anyrtc_dtls_transport* const dtls_transport, // referenced
    char* const redirect_ip, // copied
    uint16_t const redirect_port,
    uint16_t const local_port, // zeroable
    uint16_t const remote_port // zeroable
);

/*
 * Get the corresponding name for an SCTP transport state.
 */
char const * const anyrtc_sctp_transport_state_to_name(
    enum anyrtc_sctp_transport_state const state
);

/*
 * Create an SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_create(
    struct anyrtc_sctp_transport** const transportp, // de-referenced
    struct anyrtc_dtls_transport* const dtls_transport, // referenced
    uint16_t port, // zeroable
    anyrtc_data_channel_handler* const data_channel_handler, // nullable
    anyrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
    void* const arg // nullable
);

/*
 * Get the SCTP data transport instance.
 */
enum anyrtc_code anyrtc_sctp_transport_get_data_transport(
    struct anyrtc_data_transport** const transportp, // de-referenced
    struct anyrtc_sctp_transport* const sctp_transport
);

/*
 * Start the SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_start(
    struct anyrtc_sctp_transport* const transport,
    struct anyrtc_sctp_capabilities* const remote_capabilities // copied
);

/*
 * Stop and close the SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_stop(
    struct anyrtc_sctp_transport* const transport
);

/*
 * Get local SCTP capabilities of a transport.
 */
enum anyrtc_code anyrtc_sctp_transport_get_capabilities(
    struct anyrtc_sctp_capabilities** const capabilitiesp, // de-referenced
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
 * TODO: Add binary/string flag
 */
enum anyrtc_code anyrtc_data_channel_send(
    struct anyrtc_data_channel* const channel,
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
 * Translate an anyrtc return code to a string.
 */
char const* anyrtc_code_to_str(
    enum anyrtc_code const code
);

/*
 * Translate an re error to an anyrtc code.
 */
enum anyrtc_code anyrtc_error_to_code(
    const int code
);

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int anyrtc_ice_protocol_to_ipproto(
    enum anyrtc_ice_protocol const protocol
);

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum anyrtc_code anyrtc_ipproto_to_ice_protocol(
    enum anyrtc_ice_protocol* const protocolp, // de-referenced
    int const ipproto
);

/*
 * Translate an ICE protocol to str.
 */
char const * anyrtc_ice_protocol_to_str(
    enum anyrtc_ice_protocol const protocol
);

/*
 * Translate a str to an ICE protocol (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_protocol(
    enum anyrtc_ice_protocol* const protocolp, // de-referenced
    char const* const str
);

/*
 * Translate an ICE candidate type to str.
 */
char const * anyrtc_ice_candidate_type_to_str(
    enum anyrtc_ice_candidate_type const type
);

/*
 * Translate a str to an ICE candidate type (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_candidate_type(
    enum anyrtc_ice_candidate_type* const typep, // de-referenced
    char const* const str
);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const * anyrtc_ice_tcp_candidate_type_to_str(
    enum anyrtc_ice_tcp_candidate_type const type
);

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_tcp_candidate_type(
    enum anyrtc_ice_tcp_candidate_type* const typep, // de-referenced
    char const* const str
);

/*
 * Translate an ICE role to str.
 */
char const * anyrtc_ice_role_to_str(
    enum anyrtc_ice_role const role
);

/*
 * Translate a str to an ICE role (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_role(
    enum anyrtc_ice_role* const rolep, // de-referenced
    char const* const str
);

/*
 * Translate a DTLS role to str.
 */
char const * anyrtc_dtls_role_to_str(
    enum anyrtc_dtls_role const role
);

/*
 * Translate a str to a DTLS role (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_dtls_role(
    enum anyrtc_dtls_role* const rolep, // de-referenced
    char const* const str
);

/*
 * Translate a certificate sign algorithm to str.
 */
char const * anyrtc_certificate_sign_algorithm_to_str(
    enum anyrtc_certificate_sign_algorithm const algorithm
);

/*
 * Translate a str to a certificate sign algorithm (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_certificate_sign_algorithm(
    enum anyrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
    char const* const str
);



/*
 * Duplicate a string.
 */
enum anyrtc_code anyrtc_strdup(
    char** const destinationp,
    char const * const source
);

/*
 * Print a formatted string to a buffer.
 */
enum anyrtc_code anyrtc_snprintf(
    char* const destinationp,
    size_t const size,
    char* const formatter,
    ...
);

/*
 * Print a formatted string to a dynamically allocated buffer.
 */
enum anyrtc_code anyrtc_sdprintf(
    char** const destinationp,
    char* const formatter,
    ...
);
