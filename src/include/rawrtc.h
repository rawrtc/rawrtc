#pragma once
// TODO: Move this section into meson build
#define RAWRTC_DEBUG 1

#include <stdlib.h> // TODO: Why?
#include <stdbool.h> // bool
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP, ...
#include <openssl/evp.h> // EVP_PKEY

//#define ZF_LOG_LIBRARY_PREFIX rawrtc_
//#ifdef RAWRTC_DEBUG
//    #define RAWRTC_ZF_LOG_LEVEL ZF_LOG_DEBUG
//#else
//    #define RAWRTC_ZF_LOG_LEVEL ZF_LOG_WARN
//#endif
//#include <zf_log.h>

#define RAWRTC_DEBUG_LEVEL 5

#define HAVE_INTTYPES_H
#include <re.h>
#include <rew.h>
#include <usrsctp.h>

/*
 * Version
 *
 * Follows Semantic Versioning 2.0.0,
 * see: https://semver.org
 *
 * TODO: Find a way to keep this in sync with the one in CMakeLists.txt
 */
#define RAWRTC_VERSION "0.0.1"

/*
 * Return codes.
 */
enum rawrtc_code {
    RAWRTC_CODE_UNKNOWN_ERROR = -2,
    RAWRTC_CODE_NOT_IMPLEMENTED = -1,
    RAWRTC_CODE_SUCCESS = 0,
    RAWRTC_CODE_INITIALISE_FAIL,
    RAWRTC_CODE_INVALID_ARGUMENT,
    RAWRTC_CODE_NO_MEMORY,
    RAWRTC_CODE_INVALID_STATE,
    RAWRTC_CODE_UNSUPPORTED_PROTOCOL,
    RAWRTC_CODE_UNSUPPORTED_ALGORITHM,
    RAWRTC_CODE_NO_VALUE,
    RAWRTC_CODE_NO_SOCKET,
    RAWRTC_CODE_INVALID_CERTIFICATE,
    RAWRTC_CODE_INVALID_FINGERPRINT,
    RAWRTC_CODE_INSUFFICIENT_SPACE,
    RAWRTC_CODE_STILL_IN_USE,
    RAWRTC_CODE_INVALID_MESSAGE,
    RAWRTC_CODE_MESSAGE_TOO_LONG,
    RAWRTC_CODE_TRY_AGAIN_LATER,
    RAWRTC_CODE_STOP_ITERATION,
    RAWRTC_CODE_NOT_PERMITTED,
}; // IMPORTANT: Add translations for new return codes in `utils.c`!

/*
 * Certificate private key types.
 */
enum rawrtc_certificate_key_type {
    RAWRTC_CERTIFICATE_KEY_TYPE_RSA = TLS_KEYTYPE_RSA,
    RAWRTC_CERTIFICATE_KEY_TYPE_EC = TLS_KEYTYPE_EC
};

/*
 * Certificate signing hash algorithms.
 */
enum rawrtc_certificate_sign_algorithm {
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE = 0,
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256 = TLS_FINGERPRINT_SHA256,
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384,
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512
};

/*
 * Certificate encoding.
 */
enum rawrtc_certificate_encode {
    RAWRTC_CERTIFICATE_ENCODE_CERTIFICATE,
    RAWRTC_CERTIFICATE_ENCODE_PRIVATE_KEY,
    RAWRTC_CERTIFICATE_ENCODE_BOTH
};

/*
 * SDP type.
 */
enum rawrtc_sdp_type {
    RAWRTC_SDP_TYPE_OFFER,
    RAWRTC_SDP_TYPE_PROVISIONAL_ANSWER,
    RAWRTC_SDP_TYPE_ANSWER,
    RAWRTC_SDP_TYPE_ROLLBACK,
};

/*
 * ICE gather policy.
 */
enum rawrtc_ice_gather_policy {
    RAWRTC_ICE_GATHER_POLICY_ALL,
    RAWRTC_ICE_GATHER_POLICY_NOHOST,
    RAWRTC_ICE_GATHER_POLICY_RELAY
};

/*
 * ICE credential type
 */
enum rawrtc_ice_credential_type {
    RAWRTC_ICE_CREDENTIAL_TYPE_NONE,
    RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD,
    RAWRTC_ICE_CREDENTIAL_TYPE_TOKEN
};

/*
 * ICE gatherer state.
 */
enum rawrtc_ice_gatherer_state {
    RAWRTC_ICE_GATHERER_STATE_NEW,
    RAWRTC_ICE_GATHERER_STATE_GATHERING,
    RAWRTC_ICE_GATHERER_STATE_COMPLETE,
    RAWRTC_ICE_GATHERER_STATE_CLOSED
};

/*
 * ICE component.
 * Note: For now, only "RTP" will be supported/returned as we do not support
 * RTP or RTCP.
 */
enum rawrtc_ice_component {
    RAWRTC_ICE_COMPONENT_RTP,
    RAWRTC_ICE_COMPONENT_RTCP
};

/*
 * ICE role.
 */
enum rawrtc_ice_role {
    RAWRTC_ICE_ROLE_UNKNOWN = ICE_ROLE_UNKNOWN,
    RAWRTC_ICE_ROLE_CONTROLLING = ICE_ROLE_CONTROLLING,
    RAWRTC_ICE_ROLE_CONTROLLED = ICE_ROLE_CONTROLLED
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
     RAWRTC_ICE_TRANSPORT_STATE_CLOSED
 };

/*
 * DTLS role.
 */
enum rawrtc_dtls_role {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER
};

/*
 * DTLS transport state.
 */
enum rawrtc_dtls_transport_state {
    RAWRTC_DTLS_TRANSPORT_STATE_NEW,
    RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING,
    RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED,
    RAWRTC_DTLS_TRANSPORT_STATE_CLOSED,
    RAWRTC_DTLS_TRANSPORT_STATE_FAILED
};

/*
 * Data channel is unordered bit flag.
 */
enum {
    RAWRTC_DATA_CHANNEL_TYPE_IS_UNORDERED = 0x80
};

/*
 * Data channel types.
 */
enum rawrtc_data_channel_type {
    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED = 0x00,
    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED = 0x80,
    RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_RETRANSMIT = 0x01,
    RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_RETRANSMIT = 0x81,
    RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_TIMED = 0x02,
    RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_TIMED = 0x82
}; // IMPORTANT: If you add a new type, ensure that every data channel transport handles it
   //            correctly! Also, ensure this still works with the unordered bit flag above or
   //            update the implementations.

/*
 * Data channel message flags.
 */
enum rawrtc_data_channel_message_flag {
    RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_NONE = 1 << 0,
    RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_ABORTED = 1 << 1,
    RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_COMPLETE = 1 << 2,
    RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_BINARY = 1 << 3,
};

/*
 * SCTP transport state.
 */
enum rawrtc_sctp_transport_state {
    RAWRTC_SCTP_TRANSPORT_STATE_NEW,
    RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING,
    RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED,
    RAWRTC_SCTP_TRANSPORT_STATE_CLOSED
};

/*
 * ICE protocol.
 */
enum rawrtc_ice_protocol {
    RAWRTC_ICE_PROTOCOL_UDP = IPPROTO_UDP,
    RAWRTC_ICE_PROTOCOL_TCP = IPPROTO_TCP
};

/*
 * ICE candidate type.
 */
enum rawrtc_ice_candidate_type {
    RAWRTC_ICE_CANDIDATE_TYPE_HOST = ICE_CAND_TYPE_HOST,
    RAWRTC_ICE_CANDIDATE_TYPE_SRFLX = ICE_CAND_TYPE_SRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_PRFLX = ICE_CAND_TYPE_PRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_RELAY = ICE_CAND_TYPE_RELAY
};

/*
 * ICE TCP candidate type.
 */
enum rawrtc_ice_tcp_candidate_type {
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE = ICE_TCP_ACTIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE = ICE_TCP_PASSIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_SO = ICE_TCP_SO
};

/*
 * Data channel state.
 */
enum rawrtc_data_channel_state {
    RAWRTC_DATA_CHANNEL_STATE_CONNECTING,
    RAWRTC_DATA_CHANNEL_STATE_OPEN,
    RAWRTC_DATA_CHANNEL_STATE_CLOSING,
    RAWRTC_DATA_CHANNEL_STATE_CLOSED
};

/*
 * Peer connection state.
 */
enum rawrtc_peer_connection_state {
    RAWRTC_PEER_CONNECTION_STATE_NEW,
    RAWRTC_PEER_CONNECTION_STATE_CONNECTING,
    RAWRTC_PEER_CONNECTION_STATE_CONNECTED,
    RAWRTC_PEER_CONNECTION_STATE_DISCONNECTED,
    RAWRTC_PEER_CONNECTION_STATE_FAILED,
    RAWRTC_PEER_CONNECTION_STATE_CLOSED,
};


#ifdef SCTP_REDIRECT_TRANSPORT
/*
 * SCTP redirect transport states.
 * TODO: Private -> sctp_redirect_transport.h
 */
enum rawrtc_sctp_redirect_transport_state {
    RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_NEW,
    RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_OPEN,
    RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_CLOSED
};
#endif

/*
 * Data transport type.
 * TODO: private -> data_transport.h
 */
enum rawrtc_data_transport_type {
    RAWRTC_DATA_TRANSPORT_TYPE_SCTP
};

/*
 * ICE candidate storage type (internal).
 * TODO: Private
 */
enum rawrtc_ice_candidate_storage {
    RAWRTC_ICE_CANDIDATE_STORAGE_RAW,
    RAWRTC_ICE_CANDIDATE_STORAGE_LCAND,
    RAWRTC_ICE_CANDIDATE_STORAGE_RCAND,
};

/*
 * ICE server type.
 * Note: Update `ice_server_schemes` if changed.
 * TODO: private -> ice_gatherer.h
 */
enum rawrtc_ice_server_type {
    RAWRTC_ICE_SERVER_TYPE_STUN,
    RAWRTC_ICE_SERVER_TYPE_TURN
};

/*
 * ICE server transport protocol.
 * TODO: private -> ice_gatherer.h
 */
enum rawrtc_ice_server_transport {
    RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    RAWRTC_ICE_SERVER_TRANSPORT_TCP,
    RAWRTC_ICE_SERVER_TRANSPORT_DTLS,
    RAWRTC_ICE_SERVER_TRANSPORT_TLS
};

/*
 * Length of various arrays.
 * TODO: private
 */
enum {
    ICE_USERNAME_FRAGMENT_LENGTH = 32,
    ICE_PASSWORD_LENGTH = 32,
    DTLS_ID_LENGTH = 32,
};


/*
 * Struct prototypes.
 * TODO: Remove
 */
struct rawrtc_ice_server_url_context;
struct rawrtc_ice_candidate;
struct rawrtc_data_channel;
struct rawrtc_dtls_transport;
struct rawrtc_dtls_parameters;
struct rawrtc_data_channel_parameters;
struct rawrtc_data_transport;
struct rawrtc_sctp_transport;
struct rawrtc_sctp_capabilities;
struct rawrtc_peer_connection_ice_candidate;



/*
 * ICE gatherer state change handler.
 */
typedef void (rawrtc_ice_gatherer_state_change_handler)(
    enum rawrtc_ice_gatherer_state const state, // read-only
    void* const arg
);
 
/*
 * ICE gatherer error handler.
 */
typedef void (rawrtc_ice_gatherer_error_handler)(
    struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
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
typedef void (rawrtc_ice_gatherer_local_candidate_handler)(
    struct rawrtc_ice_candidate* const candidate,
    char const * const url, // read-only
    void* const arg
);

/*
 * ICE transport state change handler.
 */
typedef void (rawrtc_ice_transport_state_change_handler)(
    enum rawrtc_ice_transport_state const state,
    void* const arg
);

/*
 * ICE transport pair change handler.
 */
typedef void (rawrtc_ice_transport_candidate_pair_change_handler)(
    struct rawrtc_ice_candidate* const local, // read-only
    struct rawrtc_ice_candidate* const remote, // read-only
    void* const arg
);

/*
 * DTLS transport state change handler.
 */
typedef void (rawrtc_dtls_transport_state_change_handler)(
    enum rawrtc_dtls_transport_state const state,
    void* const arg
);

/*
 * DTLS transport error handler.
 */
typedef void (rawrtc_dtls_transport_error_handler)(
    /* TODO: error.message (probably from OpenSSL) */
    void* const arg
);

/*
 * SCTP transport state change handler.
 */
typedef void (rawrtc_sctp_transport_state_change_handler)(
    enum rawrtc_sctp_transport_state const state,
    void* const arg
);

/*
 * Data channel open handler.
 */
typedef void (rawrtc_data_channel_open_handler)(
    void* const arg
);

/*
 * Data channel buffered amount low handler.
 */
typedef void (rawrtc_data_channel_buffered_amount_low_handler)(
    void* const arg
);

/*
 * Data channel error handler.
 */
typedef void (rawrtc_data_channel_error_handler)(
    /* TODO */
    void* const arg
);

/*
 * Data channel close handler.
 */
typedef void (rawrtc_data_channel_close_handler)(
    void* const arg
);

/*
 * Data channel message handler.
 *
 * Note: `buffer` may be NULL in case partial delivery has been
 *       requested and a message has been aborted (this can only happen
 *       on partially reliable channels).
 *
 * TODO: ORTC is really unclear about that handler. Consider improving it with a PR.
 */
typedef void (rawrtc_data_channel_message_handler)(
    struct mbuf* const buffer, // nullable (in case partial delivery has been requested)
    enum rawrtc_data_channel_message_flag const flags,
    void* const arg
);

/*
 * Data channel handler.
 *
 * You should call `rawrtc_data_channel_set_options` in this handler
 * before doing anything else if you want to change behaviour of the
 * data channel.
 */
typedef void (rawrtc_data_channel_handler)(
    struct rawrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
    void* const arg
);

/*
 * Peer connection state change handler.
 */
typedef void (rawrtc_peer_connection_state_change_handler)(
    enum rawrtc_peer_connection_state const state, // read-only
    void* const arg
);

/*
 * Peer connection negotiation needed handler.
 */
typedef void (rawrtc_peer_connection_negotiation_needed_handler)(
    void* const arg
);

/*
 * Per connection local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (rawrtc_peer_connection_local_candidate_handler)(
    struct rawrtc_peer_connection_ice_candidate* const candidate,
    char const * const url, // read-only
    void* const arg
);

/*
 * Handle incoming data messages.
 * TODO: private -> dtls_transport.h
 */
typedef void (rawrtc_dtls_transport_receive_handler)(
    struct mbuf* const buffer,
    void* const arg
);

/*
 * Create the data channel (transport handler).
 * TODO: private -> data_transport.h
 */
typedef enum rawrtc_code (rawrtc_data_transport_channel_create_handler)(
    struct rawrtc_data_transport* const transport,
    struct rawrtc_data_channel* const channel, // referenced
    struct rawrtc_data_channel_parameters const * const parameters // read-only
);

/*
 * Close the data channel (transport handler).
 * TODO: private -> data_transport.h
 */
typedef enum rawrtc_code (rawrtc_data_transport_channel_close_handler)(
    struct rawrtc_data_channel* const channel
);

/*
 * Send data via the data channel (transport handler).
 * TODO: private -> data_transport.h
 */
typedef enum rawrtc_code (rawrtc_data_transport_channel_send_handler)(
    struct rawrtc_data_channel* const channel,
    struct mbuf* buffer, // nullable (if size 0), referenced
    bool const is_binary
);



/*
 * Configuration.
 * TODO: Add to a constructor... somewhere
 */
struct rawrtc_config {
    uint32_t pacing_interval;
    bool ipv4_enable;
    bool ipv6_enable;
    bool udp_enable;
    bool tcp_enable;
    enum rawrtc_certificate_sign_algorithm sign_algorithm;
    enum rawrtc_ice_server_transport ice_server_normal_transport;
    enum rawrtc_ice_server_transport ice_server_secure_transport;
    uint32_t stun_keepalive_interval;
    struct stun_conf stun_config;
};

/*
 * Message buffer.
 * TODO: private
 */
struct rawrtc_buffered_message {
    struct le le;
    struct mbuf* buffer; // referenced
    void* context; // referenced, nullable
};

/*
 * Certificate options.
 * TODO: private
 */
struct rawrtc_certificate_options {
    enum rawrtc_certificate_key_type key_type;
    char* common_name; // copied
    uint_fast32_t valid_until;
    enum rawrtc_certificate_sign_algorithm sign_algorithm;
    char* named_curve; // nullable, copied, ignored for RSA
    uint_fast32_t modulus_length; // ignored for ECC
};

/*
 * Certificate.
 * TODO: private
 */
struct rawrtc_certificate {
    struct le le;
    X509* certificate;
    EVP_PKEY* key;
    enum rawrtc_certificate_key_type key_type;
};

/*
 * ICE gather options.
 * TODO: private
 */
struct rawrtc_ice_gather_options {
    enum rawrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
};

/*
 * ICE server.
 * TODO: private
 */
struct rawrtc_ice_server {
    struct le le;
    struct list urls; // deep-copied
    char* username; // copied
    char* credential; // copied
    enum rawrtc_ice_credential_type credential_type;
};

/*
 * ICE server URL. (list element)
 * TODO: private
 */
struct rawrtc_ice_server_url {
    struct le le;
    char* url; // copied
    struct pl host; // points inside `url`
    enum rawrtc_ice_server_type type;
    enum rawrtc_ice_server_transport transport;
    struct sa ipv4_address;
    struct rawrtc_ice_server_url_dns_context* dns_a_context;
    struct sa ipv6_address;
    struct rawrtc_ice_server_url_dns_context* dns_aaaa_context;
};

/*
 * ICE server URL DNS resolve context.
 * TODO: private -> ice_gatherer.h
 */
struct rawrtc_ice_server_url_dns_context {
    uint_fast16_t dns_type;
    struct rawrtc_ice_server_url* url;
    struct rawrtc_ice_gatherer* gatherer;
    struct dns_query* dns_query;
};

/*
 * Raw ICE candidate (pending candidate).
 * TODO: private
 */
struct rawrtc_ice_candidate_raw {
    char* foundation; // copied
    uint32_t priority;
    char* ip; // copied
    enum rawrtc_ice_protocol protocol;
    uint16_t port;
    enum rawrtc_ice_candidate_type type;
    enum rawrtc_ice_tcp_candidate_type tcp_type;
    char* related_address; // copied, nullable
    uint16_t related_port;
};

/*
 * ICE candidate.
 * TODO: private
 */
struct rawrtc_ice_candidate {
    enum rawrtc_ice_candidate_storage storage_type;
    union {
        struct rawrtc_ice_candidate_raw* raw_candidate;
        struct ice_lcand* local_candidate;
        struct ice_rcand* remote_candidate;
    } candidate;
};

/*
 * ICE parameters.
 * TODO: private
 */
struct rawrtc_ice_parameters {
    char* username_fragment; // copied
    char* password; // copied
    bool ice_lite;
};

/*
 * ICE gatherer.
 * TODO: private
 */
struct rawrtc_ice_gatherer {
    enum rawrtc_ice_gatherer_state state;
    struct rawrtc_ice_gather_options* options; // referenced
    rawrtc_ice_gatherer_state_change_handler* state_change_handler; // nullable
    rawrtc_ice_gatherer_error_handler* error_handler; // nullable
    rawrtc_ice_gatherer_local_candidate_handler* local_candidate_handler; // nullable
    void* arg; // nullable
    struct list buffered_messages; // TODO: Can this be added to the candidates list?
    struct list local_candidates; // TODO: Hash list instead?
    char ice_username_fragment[ICE_USERNAME_FRAGMENT_LENGTH + 1];
    char ice_password[ICE_PASSWORD_LENGTH + 1];
    struct trice* ice;
    struct trice_conf ice_config;
    struct dnsc* dns_client;
};

/*
 * ICE transport.
 * TODO: private
 */
struct rawrtc_ice_transport {
    enum rawrtc_ice_transport_state state;
    struct rawrtc_ice_gatherer* gatherer; // referenced
    rawrtc_ice_transport_state_change_handler* state_change_handler; // nullable
    rawrtc_ice_transport_candidate_pair_change_handler* candidate_pair_change_handler; // nullable
    void* arg; // nullable
    struct rawrtc_ice_parameters* remote_parameters; // referenced
    struct rawrtc_dtls_transport* dtls_transport; // referenced, nullable
};

/*
 * DTLS fingerprint.
 * TODO: private
 */
struct rawrtc_dtls_fingerprint {
    struct le le;
    enum rawrtc_certificate_sign_algorithm algorithm;
    char* value; // copied
};

/*
 * DTLS parameters.
 * TODO: private
 */
struct rawrtc_dtls_parameters {
    enum rawrtc_dtls_role role;
    struct rawrtc_dtls_fingerprints* fingerprints;
};

/*
 * DTLS transport.
 * TODO: private
 */
struct rawrtc_dtls_transport {
    enum rawrtc_dtls_transport_state state;
    struct rawrtc_ice_transport* ice_transport; // referenced
    struct list certificates; // deep-copied
    rawrtc_dtls_transport_state_change_handler* state_change_handler; // nullable
    rawrtc_dtls_transport_error_handler* error_handler; // nullable
    void* arg; // nullable
    struct rawrtc_dtls_parameters* remote_parameters; // referenced
    enum rawrtc_dtls_role role;
    bool connection_established;
    struct list buffered_messages_in;
    struct list buffered_messages_out;
    struct list fingerprints;
    struct tls* context;
    struct dtls_sock* socket;
    struct tls_conn* connection;
    rawrtc_dtls_transport_receive_handler* receive_handler;
    void* receive_handler_arg;
};

#ifdef SCTP_REDIRECT_TRANSPORT
/*
 * Redirect transport.
 */
struct rawrtc_sctp_redirect_transport {
    enum rawrtc_sctp_redirect_transport_state state;
    struct rawrtc_dtls_transport* dtls_transport; // referenced
    uint16_t local_port;
    uint16_t remote_port;
    struct sa redirect_address;
    struct mbuf* buffer;
    int socket;
};
#endif

/*
 * Generic data transport.
 * TODO: private
 */
struct rawrtc_data_transport {
    enum rawrtc_data_transport_type type; // TODO: Can this be removed?
    void* transport;
    rawrtc_data_transport_channel_create_handler* channel_create;
    rawrtc_data_transport_channel_close_handler* channel_close;
    rawrtc_data_transport_channel_send_handler* channel_send;
};

/*
 * Data channel parameters.
 * TODO: private
 */
struct rawrtc_data_channel_parameters {
    char* label; // copied
    enum rawrtc_data_channel_type channel_type;
    uint32_t reliability_parameter; // contains either max_packet_lifetime or max_retransmit
    char* protocol; // copied
    bool negotiated;
    uint16_t id;
};

/*
 * Data channel options.
 * TODO: private
 */
struct rawrtc_data_channel_options {
    bool deliver_partially;
};

/*
 * SCTP capabilities.
 * TODO: private
 */
struct rawrtc_sctp_capabilities {
    uint64_t max_message_size;
};

/*
 * SCTP transport.
 * TODO: private
 */
struct rawrtc_sctp_transport {
    enum rawrtc_sctp_transport_state state;
    uint16_t port;
    uint64_t remote_maximum_message_size;
    struct rawrtc_dtls_transport* dtls_transport; // referenced
    rawrtc_data_channel_handler* data_channel_handler; // nullable
    rawrtc_sctp_transport_state_change_handler* state_change_handler; // nullable
    void* arg; // nullable
    struct list buffered_messages_outgoing;
    struct mbuf* buffer_dcep_inbound;
    struct sctp_rcvinfo info_dcep_inbound;
    struct rawrtc_data_channel** channels;
    uint_fast16_t n_channels;
    uint_fast16_t current_channel_sid;
    FILE* trace_handle;
    struct socket* socket;
    uint_fast8_t flags;
    struct rawrtc_data_transport* data_transport; // referenced
};

/*
 * SCTP data channel context.
 * TODO: private
 */
struct rawrtc_sctp_data_channel_context {
    uint16_t sid;
    uint_fast8_t flags;
    struct mbuf* buffer_inbound;
    struct sctp_rcvinfo info_inbound;
};

/*
 * Data channel.
 * TODO: private
 */
struct rawrtc_data_channel {
    uint_fast8_t flags;
    enum rawrtc_data_channel_state state;
    struct rawrtc_data_transport* transport; // referenced
    void* transport_arg; // referenced
    struct rawrtc_data_channel_parameters* parameters; // referenced
    struct rawrtc_data_channel_options* options; // nullable, referenced
    rawrtc_data_channel_open_handler* open_handler; // nullable
    rawrtc_data_channel_buffered_amount_low_handler* buffered_amount_low_handler; // nullable
    rawrtc_data_channel_error_handler* error_handler; // nullable
    rawrtc_data_channel_close_handler* close_handler; // nullable
    rawrtc_data_channel_message_handler* message_handler; // nullable
    void* arg; // nullable
};

/*
 * Peer connection configuration.
 */
struct rawrtc_peer_connection_configuration {
    enum rawrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
    struct list certificates;
    bool sctp_sdp_05;
};

/*
 * Peer connection ICE candidate.
 * TODO: private
 */
struct rawrtc_peer_connection_ice_candidate {
    struct le le;
    struct rawrtc_ice_candidate* candidate;
    char* mid;
    int16_t media_line_index;
    char* username_fragment;
};

/*
 * Peer connection description.
 * TODO: private
 */
struct rawrtc_peer_connection_description {
    struct rawrtc_peer_connection* connection;
    enum rawrtc_sdp_type type;
    bool trickle_ice;
    char* bundled_mids;
    char* remote_media_line;
    uint8_t media_line_index;
    char* mid;
    bool sctp_sdp_05;
    bool end_of_candidates;
    struct list ice_candidates;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct rawrtc_sctp_capabilities* sctp_capabilities;
    uint16_t sctp_port;
    struct mbuf* sdp;
};

/*
 * Peer connection context.
 * TODO: private
 */
struct rawrtc_peer_connection_context {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* ice_gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct list certificates;
    char dtls_id[DTLS_ID_LENGTH + 1];
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_data_transport* data_transport;
};

/*
 * Peer connection.
 * TODO: private
 */
struct rawrtc_peer_connection {
    enum rawrtc_peer_connection_state connection_state;
    struct rawrtc_peer_connection_configuration* configuration; // referenced
    rawrtc_peer_connection_negotiation_needed_handler* negotiation_needed_handler; // nullable
    rawrtc_peer_connection_local_candidate_handler* local_candidate_handler; // nullable
    rawrtc_peer_connection_state_change_handler* connection_state_change_handler; // nullable
    enum rawrtc_data_transport_type data_transport_type;
    struct rawrtc_peer_connection_description* local_description; // referenced
    struct rawrtc_peer_connection_description* remote_description; // referenced
    struct rawrtc_peer_connection_context context;
    rawrtc_data_channel_handler* data_channel_handler; // nullable
    void* arg; // nullable
};

/*
 * Layers.
 * TODO: private
 */
enum {
    RAWRTC_LAYER_SCTP = 20,
    RAWRTC_LAYER_DTLS_SRTP_STUN = 10, // TODO: Pretty sure we are able to detect STUN earlier
    RAWRTC_LAYER_ICE = 0,
    RAWRTC_LAYER_STUN = -10,
    RAWRTC_LAYER_TURN = -10
};



/*
 * ICE candidates.
 */
struct rawrtc_ice_candidates {
    size_t n_candidates;
    struct rawrtc_ice_candidate* candidates[];
};

/*
 * DTLS fingerprints
 */
struct rawrtc_dtls_fingerprints {
    size_t n_fingerprints;
    struct rawrtc_dtls_fingerprint* fingerprints[];
};



/*
 * Initialise rawrtc. Must be called before making a call to any other
 * function.
 */
enum rawrtc_code rawrtc_init();

/*
 * Close rawrtc and free up all resources.
 */
enum rawrtc_code rawrtc_close();

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
enum rawrtc_code rawrtc_certificate_options_create(
    struct rawrtc_certificate_options** const optionsp, // de-referenced
    enum rawrtc_certificate_key_type const key_type,
    char* common_name, // nullable, copied
    uint_fast32_t valid_until,
    enum rawrtc_certificate_sign_algorithm sign_algorithm,
    char* named_curve, // nullable, copied, ignored for RSA
    uint_fast32_t modulus_length // ignored for ECC
);

/*
 * Create and generate a self-signed certificate.
 *
 * Sane and safe default options will be applied if `options` is
 * `NULL`.
 */
enum rawrtc_code rawrtc_certificate_generate(
    struct rawrtc_certificate** const certificatep,
    struct rawrtc_certificate_options* options // nullable
);

/*
 * TODO http://draft.ortc.org/#dom-rtccertificate
 * rawrtc_certificate_from_bytes
 * rawrtc_certificate_get_expires
 * rawrtc_certificate_get_fingerprint
 * rawrtc_certificate_get_algorithm
 */

/*
 * Create an ICE candidate.
 */
enum rawrtc_code rawrtc_ice_candidate_create(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    char* const foundation, // copied
    uint32_t const priority,
    char* const ip, // copied
    enum rawrtc_ice_protocol const protocol,
    uint16_t const port,
    enum rawrtc_ice_candidate_type const type,
    enum rawrtc_ice_tcp_candidate_type const tcp_type,
    char* const related_address, // copied, nullable
    uint16_t const related_port
);

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_foundation(
    char** const foundationp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's priority.
 */
enum rawrtc_code rawrtc_ice_candidate_get_priority(
    uint32_t* const priorityp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_ip(
    char** const ipp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's protocol.
 */
enum rawrtc_code rawrtc_ice_candidate_get_protocol(
    enum rawrtc_ice_protocol* const protocolp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's port.
 */
enum rawrtc_code rawrtc_ice_candidate_get_port(
    uint16_t* const portp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's type.
 */
enum rawrtc_code rawrtc_ice_candidate_get_type(
    enum rawrtc_ice_candidate_type* typep, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's TCP type.
 * `*typep` will be set to `NULL` in case the protocol is not TCP.
 */
enum rawrtc_code rawrtc_ice_candidate_get_tcp_type(
    enum rawrtc_ice_tcp_candidate_type* typep, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced or `NULL` in case no related address exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_address(
    char** const related_addressp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port or `0` in case no related address exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_port(
    uint16_t* const related_portp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Create a new ICE parameters instance.
 */
enum rawrtc_code rawrtc_ice_parameters_create(
    struct rawrtc_ice_parameters** const parametersp, // de-referenced
    char* const username_fragment, // copied
    char* const password, // copied
    bool const ice_lite
);

/*
 * Get the ICE parameter's username fragment value.
 * `*username_fragmentp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_username_fragment(
    char** const username_fragmentp, // de-referenced
    struct rawrtc_ice_parameters* const parameters
);

/*
 * Get the ICE parameter's password value.
 * `*passwordp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_password(
    char** const passwordp, // de-referenced
    struct rawrtc_ice_parameters* const parameters
);

/*
 * Get the ICE parameter's ICE lite value.
 */
enum rawrtc_code rawrtc_ice_parameters_get_ice_lite(
    bool* const ice_litep, // de-referenced
    struct rawrtc_ice_parameters* const parameters
);

/*
 * Create a new ICE gather options instance.
 */
enum rawrtc_code rawrtc_ice_gather_options_create(
    struct rawrtc_ice_gather_options** const optionsp, // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy
);

/*
 * TODO
 * rawrtc_ice_server_list_*
 */

/*
 * Add an ICE server to the gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_add_server(
    struct rawrtc_ice_gather_options* const options,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

/*
 * TODO (from RTCIceServer interface)
 * rawrtc_ice_server_set_username
 * rawrtc_ice_server_set_credential
 * rawrtc_ice_server_set_credential_type
 */

/*
 * Get the corresponding name for an ICE gatherer state.
 */
char const * const rawrtc_ice_gatherer_state_to_name(
    enum rawrtc_ice_gatherer_state const state
);

 /*
  * Create a new ICE gatherer.
  */
enum rawrtc_code rawrtc_ice_gatherer_create(
    struct rawrtc_ice_gatherer** const gathererp, // de-referenced
    struct rawrtc_ice_gather_options* const options, // referenced
    rawrtc_ice_gatherer_state_change_handler* const state_change_handler, // nullable
    rawrtc_ice_gatherer_error_handler* const error_handler, // nullable
    rawrtc_ice_gatherer_local_candidate_handler* const local_candidate_handler, // nullable
    void* const arg // nullable
);

/*
 * Close the ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_close(
    struct rawrtc_ice_gatherer* const gatherer
);

/*
 * Start gathering using an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_gather(
    struct rawrtc_ice_gatherer* const gatherer,
    struct rawrtc_ice_gather_options* const options // referenced, nullable
);

/*
 * TODO (from RTCIceGatherer interface)
 * rawrtc_ice_gatherer_get_component
 * rawrtc_ice_gatherer_get_state
 */

/*
 * Get local ICE parameters of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_parameters(
    struct rawrtc_ice_parameters** const parametersp, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer
);

/*
 * Get local ICE candidates of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_candidates(
    struct rawrtc_ice_candidates** const candidatesp, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer
);

/*
 * TODO (from RTCIceGatherer interface)
 * rawrtc_ice_gatherer_create_associated_gatherer (unsupported)
 * rawrtc_ice_gatherer_set_state_change_handler
 * rawrtc_ice_gatherer_set_error_handler
 * rawrtc_ice_gatherer_set_local_candidate_handler
 */

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const rawrtc_ice_transport_state_to_name(
    enum rawrtc_ice_transport_state const state
);

/*
 * Create a new ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_create(
    struct rawrtc_ice_transport** const transportp, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer, // referenced, nullable
    rawrtc_ice_transport_state_change_handler* const state_change_handler, // nullable
    rawrtc_ice_transport_candidate_pair_change_handler* const candidate_pair_change_handler, // nullable
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
 * rawrtc_ice_transport_get_state
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
 * Create a new DTLS fingerprint instance.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_create(
    struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum rawrtc_certificate_sign_algorithm const algorithm,
    char* const value // copied
);

/*
 * TODO
 * rawrtc_dtls_fingerprint_get_algorithm
 * rawrtc_dtls_fingerprint_get_value
 */

/*
 * Create a new DTLS parameters instance.
 */
enum rawrtc_code rawrtc_dtls_parameters_create(
    struct rawrtc_dtls_parameters** const parametersp, // de-referenced
    enum rawrtc_dtls_role const role,
    struct rawrtc_dtls_fingerprint* const fingerprints[], // referenced (each item)
    size_t const n_fingerprints
);

/*
 * Get the DTLS parameter's role value.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_role(
    enum rawrtc_dtls_role* rolep, // de-referenced
    struct rawrtc_dtls_parameters* const parameters
);

/*
 * Get the DTLS parameter's fingerprint array.
 * `*fingerprintsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_fingerprints(
    struct rawrtc_dtls_fingerprints** const fingerprintsp, // de-referenced
    struct rawrtc_dtls_parameters* const parameters
);

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum rawrtc_code rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(
    enum rawrtc_certificate_sign_algorithm* const sign_algorithmp, // de-referenced
    struct rawrtc_dtls_fingerprint* const fingerprint
);

/*
 * Get the DTLS certificate's fingerprint value.
 * `*valuep` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_fingerprint_get_value(
    char** const valuep, // de-referenced
    struct rawrtc_dtls_fingerprint* const fingerprint
);

/*
* Get the corresponding name for an ICE transport state.
*/
char const * const rawrtc_dtls_transport_state_to_name(
    enum rawrtc_dtls_transport_state const state
);

/*
 * Create a new DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_create(
    struct rawrtc_dtls_transport** const transportp, // de-referenced
    struct rawrtc_ice_transport* const ice_transport, // referenced
    struct rawrtc_certificate* const certificates[], // copied (each item)
    size_t const n_certificates,
    rawrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
    rawrtc_dtls_transport_error_handler* const error_handler, // nullable
    void* const arg // nullable
);

/*
 * Start the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_start(
    struct rawrtc_dtls_transport* const transport,
    struct rawrtc_dtls_parameters* const remote_parameters // copied
);

/*
 * Stop and close the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_stop(
    struct rawrtc_dtls_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * rawrtc_certificate_list_*
 * rawrtc_dtls_transport_get_certificates
 * rawrtc_dtls_transport_get_transport
 * rawrtc_dtls_transport_get_state
 */

/*
 * Get local DTLS parameters of a transport.
 */
enum rawrtc_code rawrtc_dtls_transport_get_local_parameters(
    struct rawrtc_dtls_parameters** const parametersp, // de-referenced
    struct rawrtc_dtls_transport* const transport
);

/*
 * TODO (from RTCIceTransport interface)
 * rawrtc_dtls_transport_get_remote_parameters
 * rawrtc_dtls_transport_get_remote_certificates
 * rawrtc_dtls_transport_set_state_change_handler
 * rawrtc_dtls_transport_set_error_handler
 */

#ifdef SCTP_REDIRECT_TRANSPORT
/*
 * Create an SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_create(
    struct rawrtc_sctp_redirect_transport** const transportp, // de-referenced
    struct rawrtc_dtls_transport* const dtls_transport, // referenced
    uint16_t const port, // zeroable
    char* const redirect_ip, // copied
    uint16_t const redirect_port
);

/*
 * Start an SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_start(
    struct rawrtc_sctp_redirect_transport* const transport,
    struct rawrtc_sctp_capabilities const * const remote_capabilities, // copied
    uint16_t remote_port // zeroable
);

/*
 * Stop and close the SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_stop(
    struct rawrtc_sctp_redirect_transport* const transport
);

/*
 * Get the redirected local SCTP port of the SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_get_port(
    uint16_t* const portp, // de-referenced
    struct rawrtc_sctp_redirect_transport* const transport
);
#endif

/*
 * Create a new SCTP transport capabilities instance.
 */
enum rawrtc_code rawrtc_sctp_capabilities_create(
        struct rawrtc_sctp_capabilities** const capabilitiesp, // de-referenced
        uint64_t const max_message_size
);

/*
 * Get the SCTP parameter's maximum message size value.
 */
enum rawrtc_code rawrtc_sctp_capabilities_get_max_message_size(
        uint64_t* const max_message_sizep, // de-referenced
        struct rawrtc_sctp_capabilities* const capabilities
);

/*
 * Get the corresponding name for an SCTP transport state.
 */
char const * const rawrtc_sctp_transport_state_to_name(
    enum rawrtc_sctp_transport_state const state
);

/*
 * Create an SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_create(
    struct rawrtc_sctp_transport** const transportp, // de-referenced
    struct rawrtc_dtls_transport* const dtls_transport, // referenced
    uint16_t port, // zeroable
    rawrtc_data_channel_handler* const data_channel_handler, // nullable
    rawrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
    void* const arg // nullable
);

/*
 * Get the SCTP data transport instance.
 */
enum rawrtc_code rawrtc_sctp_transport_get_data_transport(
    struct rawrtc_data_transport** const transportp, // de-referenced
    struct rawrtc_sctp_transport* const sctp_transport // referenced
);

/*
 * Start the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_start(
    struct rawrtc_sctp_transport* const transport,
    struct rawrtc_sctp_capabilities const * const remote_capabilities, // copied
    uint16_t remote_port // zeroable
);

/*
 * Stop and close the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_stop(
    struct rawrtc_sctp_transport* const transport
);

/*
 * TODO (from RTCSctpTransport interface)
 * rawrtc_sctp_transport_get_transport
 * rawrtc_sctp_transport_get_state
 */

/*
 * Get the local port of the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_get_port(
    uint16_t* const portp, // de-referenced
    struct rawrtc_sctp_transport* const transport
);

/*
 * Get the local SCTP transport capabilities (static).
 */
enum rawrtc_code rawrtc_sctp_transport_get_capabilities(
    struct rawrtc_sctp_capabilities** const capabilitiesp // de-referenced
);

/*
 * TODO (from RTCSctpTransport interface)
 * rawrtc_sctp_transport_set_data_channel_handler
 */

/*
 * Create data channel parameters.
 *
 * For `RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_*`, the reliability parameter
 * is being ignored.
 *
 * When using `RAWRTC_DATA_CHANNEL_TYPE_*_RETRANSMIT`, the reliability
 * parameter specifies the number of times a retransmission occurs if
 * not acknowledged before the message is being discarded.
 *
 * When using `RAWRTC_DATA_CHANNEL_TYPE_*_TIMED`, the reliability
 * parameter specifies the time window in milliseconds during which
 * (re-)transmissions may occur before the message is being discarded.
 *
 * In case `negotiated` is set to `false`, the `id` is being ignored.
 */
enum rawrtc_code rawrtc_data_channel_parameters_create(
    struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
    char const * const label, // copied, nullable
    enum rawrtc_data_channel_type const channel_type,
    uint32_t const reliability_parameter,
    char const * const protocol, // copied
    bool const negotiated,
    uint16_t const id
);

/*
 * Get the label from the data channel parameters.
 * Return `RAWRTC_CODE_NO_VALUE` in case no label has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*parameters*
 * must be unreferenced.
 */
enum rawrtc_code rawrtc_data_channel_parameters_get_label(
    char** const labelp, // de-referenced
    struct rawrtc_data_channel_parameters* const parameters
);

/*
 * TODO
 * rawrtc_data_channel_parameters_get_channel_type
 * rawrtc_data_channel_parameters_get_reliability_parameter
 */

/*
 * Get the protocol from the data channel parameters.
 * Return `RAWRTC_CODE_NO_VALUE` in case no protocol has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*protocolp*
 * must be unreferenced.
 */
enum rawrtc_code rawrtc_data_channel_parameters_get_protocol(
    char** const protocolp, // de-referenced
    struct rawrtc_data_channel_parameters* const parameters
);

/*
 * TODO
 * rawrtc_data_channel_parameters_get_negotiated
 * rawrtc_data_channel_parameters_get_id
 */

/*
 * Create data channel options.
 *
 * - `deliver_partially`: Enable this if you want to receive partial
 *   messages. Disable if messages should arrive complete. If enabled,
 *   message chunks will be delivered until the message is complete.
 *   Other messages' chunks WILL NOT be interleaved on the same channel.
 */
enum rawrtc_code rawrtc_data_channel_options_create(
    struct rawrtc_data_channel_options** const optionsp, // de-referenced
    bool const deliver_partially
);

/*
 * Get the corresponding name for a data channel state.
 */
char const * const rawrtc_data_channel_state_to_name(
    enum rawrtc_data_channel_state const state
);

/*
 * Create a data channel.
 */
enum rawrtc_code rawrtc_data_channel_create(
    struct rawrtc_data_channel** const channelp, // de-referenced
    struct rawrtc_data_transport* const transport, // referenced
    struct rawrtc_data_channel_parameters* const parameters, // referenced
    struct rawrtc_data_channel_options* const options, // nullable, referenced
    rawrtc_data_channel_open_handler* const open_handler, // nullable
    rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    rawrtc_data_channel_error_handler* const error_handler, // nullable
    rawrtc_data_channel_close_handler* const close_handler, // nullable
    rawrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg // nullable
);

/*
 * Set the argument of a data channel that is passed to the various
 * handlers.
 */
enum rawrtc_code rawrtc_data_channel_set_arg(
    struct rawrtc_data_channel* const channel,
    void* const arg // nullable
);

/*
 * Set options on a data channel.
 *
 * Note: This function must be called directly after creation of the
 * data channel (either by explicitly creating it or implicitly in form
 * of the data channel handler callback) and before calling any other
 * data channel function.
 */
enum rawrtc_code rawrtc_data_channel_set_options(
    struct rawrtc_data_channel* const channel,
    struct rawrtc_data_channel_options* options // nullable, referenced
);

/*
 * Close the data channel.
 */
enum rawrtc_code rawrtc_data_channel_close(
    struct rawrtc_data_channel* const channel
);

/*
 * Send data via the data channel.
 */
enum rawrtc_code rawrtc_data_channel_send(
    struct rawrtc_data_channel* const channel,
    struct mbuf* const buffer, // nullable (if empty message), referenced
    bool const is_binary
);

/*
 * TODO (from RTCDataChannel interface)
 * rawrtc_data_channel_get_transport
 * rawrtc_data_channel_get_ready_state
 * rawrtc_data_channel_get_buffered_amount
 * rawrtc_data_channel_get_buffered_amount_low_threshold
 * rawrtc_data_channel_set_buffered_amount_low_threshold
 */

/*
 * Unset the handler argument and all handlers of the data channel.
 */
enum rawrtc_code rawrtc_data_channel_unset_handlers(
    struct rawrtc_data_channel* const channel
);

/*
 * Get the data channel's parameters.
 */
enum rawrtc_code rawrtc_data_channel_get_parameters(
    struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
    struct rawrtc_data_channel* const channel
);

/*
 * Set the data channel's open handler.
 */
enum rawrtc_code rawrtc_data_channel_set_open_handler(
    struct rawrtc_data_channel* const channel,
    rawrtc_data_channel_open_handler* const open_handler // nullable
);

/*
 * Set the data channel's buffered amount low handler.
 */
enum rawrtc_code rawrtc_data_channel_set_buffered_amount_low_handler(
    struct rawrtc_data_channel* const channel,
    rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler // nullable
);

/*
 * Set the data channel's error handler.
 */
enum rawrtc_code rawrtc_data_channel_set_error_handler(
    struct rawrtc_data_channel* const channel,
    rawrtc_data_channel_error_handler* const error_handler // nullable
);

/*
 * Set the data channel's close handler.
 */
enum rawrtc_code rawrtc_data_channel_set_close_handler(
    struct rawrtc_data_channel* const channel,
    rawrtc_data_channel_close_handler* const close_handler // nullable
);

/*
 * Set the data channel's message handler.
 */
enum rawrtc_code rawrtc_data_channel_set_message_handler(
    struct rawrtc_data_channel* const channel,
    rawrtc_data_channel_message_handler* const message_handler // nullable
);

/*
 * Get the corresponding name for a peer connection state.
 */
char const * const rawrtc_peer_connection_state_to_name(
    enum rawrtc_peer_connection_state const state
);

/*
 * Create a new peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_create(
    struct rawrtc_peer_connection_configuration** const configurationp, // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy
);

/*
 * Add an ICE server to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_server(
    struct rawrtc_peer_connection_configuration* const configuration,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

/*
 * Set whether to use legacy SDP for data channel parameter encoding.
 * Note: Legacy SDP for data channels is on by default due to parsing problems in Chrome.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_sdp_05(
    struct rawrtc_peer_connection_configuration* configuration,
    bool const on
);

/*
 * Create a description by parsing it from SDP.
 */
enum rawrtc_code rawrtc_peer_connection_description_create(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    enum rawrtc_sdp_type const type,
    char const* const sdp
);

/*
 * Get the SDP type of the description.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp_type(
    enum rawrtc_sdp_type* const typep, // de-referenced
    struct rawrtc_peer_connection_description* const description
);

/*
 * Get the SDP of the description.
 * `*sdpp` will be set to a copy of the SDP that must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp(
    char** const sdpp, // de-referenced
    struct rawrtc_peer_connection_description* const description
);

/*
 * Create a new ICE candidate from SDP.
 *
 * Note: This is equivalent to creating an `RTCIceCandidate` from an
 *       `RTCIceCandidateInit` instance in the W3C WebRTC
 *       specification.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_create(
    struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced
    char* const sdp,
    char* const mid, // nullable, copied
    uint8_t const* const media_line_index, // nullable, copied
    char* const username_fragment // nullable, copied
);

/*
 * Encode the ICE candidate into SDP.
 * `*sdpp` will be set to a copy of the SDP attribute that must be
 * unreferenced.
 *
 * Note: This is equivalent to the `candidate` attribute of the W3C
 *       WebRTC specification's `RTCIceCandidateInit`.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp(
    char** const sdpp, // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Get the media stream identification tag the ICE candidate is
 * associated to.
 * Return `RAWRTC_CODE_NO_VALUE` in case no 'mid' has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*midp* must
 * be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp_mid(
    char** const midp, // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Get the media stream line index the ICE candidate is associated to.
 * Return `RAWRTC_CODE_NO_VALUE` in case no media line index has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp_media_line_index(
    uint8_t* const media_line_index, // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Get the username fragment the ICE candidate is associated to.
 * Return `RAWRTC_CODE_NO_VALUE` in case no username fragment has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*username_fragmentp* must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_username_fragment(
    char** const username_fragmentp, // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Get the underlying ORTC ICE candidate from the ICE candidate.
 * `*ortc_candidatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_ortc_candidate(
    struct rawrtc_ice_candidate** const ortc_candidatep, // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Create a new peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create(
    struct rawrtc_peer_connection** const connectionp, // de-referenced
    struct rawrtc_peer_connection_configuration* configuration, // referenced
    rawrtc_peer_connection_negotiation_needed_handler* const negotiation_needed_handler, // nullable
    rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler, // nullable
    rawrtc_peer_connection_state_change_handler* const connection_state_change_handler, //nullable
    void* const arg // nullable
);

/*
* Create an offer.
*/
enum rawrtc_code rawrtc_peer_connection_create_offer(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection,
    bool const ice_restart
);

/*
 * Create an answer.
 */
enum rawrtc_code rawrtc_peer_connection_create_answer(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set and apply the local description.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_description(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_description* const description // referenced
);

/*
 * Set and apply the remote description.
 */
enum rawrtc_code rawrtc_peer_connection_set_remote_description(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_description* const description // referenced
);

/*
 * Add an ICE candidate to the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_add_ice_candidate(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Create a data channel on a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create_data_channel(
    struct rawrtc_data_channel** const channelp, // de-referenced
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_data_channel_parameters* const parameters, // referenced
    struct rawrtc_data_channel_options* const options, // nullable, referenced
    rawrtc_data_channel_open_handler* const open_handler, // nullable
    rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    rawrtc_data_channel_error_handler* const error_handler, // nullable
    rawrtc_data_channel_close_handler* const close_handler, // nullable
    rawrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg // nullable
);

/*
 * Get local description.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_description(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
* Get remote description.
*/
enum rawrtc_code rawrtc_peer_connection_get_remote_description(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection
);



/*
 * Translate a rawrtc return code to a string.
 */
char const* rawrtc_code_to_str(
    enum rawrtc_code const code
);

/*
 * Translate an re error to a rawrtc code.
 */
enum rawrtc_code rawrtc_error_to_code(
    const int code
);

/*
 * Translate an ICE gather policy to str.
 */
char const * rawrtc_ice_gather_policy_to_str(
    enum rawrtc_ice_gather_policy const policy
);

/*
 * Translate a str to an ICE gather policy (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_gather_policy(
    enum rawrtc_ice_gather_policy* const policyp, // de-referenced
    char const* const str
);

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int rawrtc_ice_protocol_to_ipproto(
    enum rawrtc_ice_protocol const protocol
);

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum rawrtc_code rawrtc_ipproto_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp, // de-referenced
    int const ipproto
);

/*
 * Translate an ICE protocol to str.
 */
char const * rawrtc_ice_protocol_to_str(
    enum rawrtc_ice_protocol const protocol
);

/*
 * Translate a str to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp, // de-referenced
    char const* const str
);

/*
 * Translate an ICE candidate type to str.
 */
char const * rawrtc_ice_candidate_type_to_str(
    enum rawrtc_ice_candidate_type const type
);

/*
 * Translate a str to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep, // de-referenced
    char const* const str
);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const * rawrtc_ice_tcp_candidate_type_to_str(
    enum rawrtc_ice_tcp_candidate_type const type
);

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
    char const* const str
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

/*
 * Translate a DTLS role to str.
 */
char const * rawrtc_dtls_role_to_str(
    enum rawrtc_dtls_role const role
);

/*
 * Translate a str to a DTLS role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_dtls_role(
    enum rawrtc_dtls_role* const rolep, // de-referenced
    char const* const str
);

/*
 * Translate a certificate sign algorithm to str.
 */
char const * rawrtc_certificate_sign_algorithm_to_str(
    enum rawrtc_certificate_sign_algorithm const algorithm
);

/*
 * Translate a str to a certificate sign algorithm (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_certificate_sign_algorithm(
    enum rawrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
    char const* const str
);

/*
 * Translate an SDP type to str.
 */
char const * rawrtc_sdp_type_to_str(
    enum rawrtc_sdp_type const type
);

/*
 * Translate a str to an SDP type.
 */
enum rawrtc_code rawrtc_str_to_sdp_type(
    enum rawrtc_sdp_type* const typep, // de-referenced
    char const* const str
);



/*
 * Duplicate a string.
 */
enum rawrtc_code rawrtc_strdup(
    char** const destinationp,
    char const * const source
);

/*
 * Print a formatted string to a buffer.
 */
enum rawrtc_code rawrtc_snprintf(
    char* const destinationp,
    size_t const size,
    char* const formatter,
    ...
);

/*
 * Print a formatted string to a dynamically allocated buffer.
 */
enum rawrtc_code rawrtc_sdprintf(
    char** const destinationp,
    char* const formatter,
    ...
);

/*
 * Convert a list to a dynamically allocated array.
 * If `reference` is set to `true`, each item in the list will be
 * referenced.
 *
 * Note: In case the list is empty, `*lengthp` will be set to `0` and
 *       `*arrayp` will be set to `NULL`.
 */
enum rawrtc_code rawrtc_list_to_array(
    void*** const arrayp, // de-referenced
    size_t* const lengthp, // de-referenced
    struct list const* const list,
    bool reference
);
