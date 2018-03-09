#pragma once
#include <stdbool.h> // bool
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP, ...

// TODO: Make this a build configuration
#define RAWRTC_DEBUG_LEVEL 5

#define HAVE_INTTYPES_H
#include <re.h>
#include <rew.h>
#include <rawrtcc.h>
#include <rawrtcdc.h>

/*
 * Version
 *
 * Follows Semantic Versioning 2.0.0,
 * see: https://semver.org
 *
 * TODO: Find a way to keep this in sync with the one in CMakeLists.txt
 */
#define RAWRTC_VERSION "0.2.1"

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
 * Signalling state.
 */
enum rawrtc_signaling_state {
    RAWRTC_SIGNALING_STATE_STABLE,
    RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER,
    RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER,
    RAWRTC_SIGNALING_STATE_HAVE_LOCAL_PROVISIONAL_ANSWER,
    RAWRTC_SIGNALING_STATE_HAVE_REMOTE_PROVISIONAL_ANSWER,
    RAWRTC_SIGNALING_STATE_CLOSED
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

/*
 * Length of various arrays.
 */
enum {
    ICE_USERNAME_FRAGMENT_LENGTH = 16,
    ICE_PASSWORD_LENGTH = 32,
    DTLS_ID_LENGTH = 32,
};



/*
 * Configuration.
 */
struct rawrtc_config;

/*
 * ICE gather options.
 */
struct rawrtc_ice_gather_options;

/*
 * ICE server.
 */
struct rawrtc_ice_server;

/*
 * ICE candidate.
 */
struct rawrtc_ice_candidate;

/*
 * ICE parameters.
 */
struct rawrtc_ice_parameters;

/*
 * ICE gatherer.
 */
struct rawrtc_ice_gatherer;

/*
 * ICE transport.
 */
struct rawrtc_ice_transport;

/*
 * DTLS fingerprint.
 */
struct rawrtc_dtls_fingerprint;

/*
 * DTLS parameters.
 */
struct rawrtc_dtls_parameters;

/*
 * DTLS transport.
 */
struct rawrtc_dtls_transport;

/*
 * Peer connection configuration.
 */
struct rawrtc_peer_connection_configuration;

/*
 * Peer connection ICE candidate.
 */
struct rawrtc_peer_connection_ice_candidate;

/*
 * Peer connection description.
 */
struct rawrtc_peer_connection_description;

/*
 * Peer connection.
 */
struct rawrtc_peer_connection;

/*
 * Layers.
 */
enum {
    RAWRTC_LAYER_SCTP = 20,
    RAWRTC_LAYER_DTLS_SRTP_STUN = 10, // TODO: Pretty sure we are able to detect STUN earlier
    RAWRTC_LAYER_ICE = 0,
    RAWRTC_LAYER_STUN = -10,
    RAWRTC_LAYER_TURN = -10
};



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
    struct rawrtc_ice_candidate* const candidate, // read-only, nullable
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
 * Peer connection state change handler.
 */
typedef void (rawrtc_peer_connection_state_change_handler)(
    enum rawrtc_peer_connection_state const state, // read-only
    void* const arg
);

/*
 * Negotiation needed handler.
 */
typedef void (rawrtc_negotiation_needed_handler)(
    void* const arg
);

/*
 * Peer connection ICE local candidate handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (rawrtc_peer_connection_local_candidate_handler)(
    struct rawrtc_peer_connection_ice_candidate* const candidate,
    char const * const url, // read-only
    void* const arg
);

/*
 * Peer connection ICE local candidate error handler.
 * Note: 'candidate' and 'url' will be NULL in case gathering is complete.
 * 'url' will be NULL in case a host candidate has been gathered.
 */
typedef void (rawrtc_peer_connection_local_candidate_error_handler)(
    struct rawrtc_peer_connection_ice_candidate* const candidate, // read-only, nullable
    char const * const url, // read-only
    uint16_t const error_code, // read-only
    char const * const error_text, // read-only
    void* const arg
);

/*
 * Signaling state handler.
 */
typedef void (rawrtc_signaling_state_change_handler)(
    enum rawrtc_signaling_state const state, // read-only
    void* const arg
);



/*
 * Certificates.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_certificates {
    size_t n_certificates;
    struct rawrtc_certificate* certificates[];
};

/*
 * ICE servers.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_ice_servers {
    size_t n_servers;
    struct rawrtc_ice_server* servers[];
};

/*
 * ICE candidates.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_ice_candidates {
    size_t n_candidates;
    struct rawrtc_ice_candidate* candidates[];
};

/*
 * DTLS fingerprints.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_dtls_fingerprints {
    size_t n_fingerprints;
    struct rawrtc_dtls_fingerprint* fingerprints[];
};



/*
 * Initialise rawrtc. Must be called before making a call to any other
 * function.
 *
 * Note: In case `init_re` is not set to `true`, you MUST initialise
 *       re yourselves before calling this function.
 */
enum rawrtc_code rawrtc_init(
    bool const init_re
);

/*
 * Close rawrtc and free up all resources.
 *
 * Note: In case `close_re` is not set to `true`, you MUST close
 *       re yourselves.
 */
enum rawrtc_code rawrtc_close(
    bool const close_re
);

/*
 * Create an ICE candidate.
 * `*candidatep` must be unreferenced.
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
 * Return `RAWRTC_CODE_NO_VALUE` in case the protocol is not TCP.
 */
enum rawrtc_code rawrtc_ice_candidate_get_tcp_type(
    enum rawrtc_ice_tcp_candidate_type* typep, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related address exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_address(
    char** const related_addressp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
);

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related port exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_port(
    uint16_t* const related_portp, // de-referenced
    struct rawrtc_ice_candidate* const candidate
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
 * Translate a pl to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp, // de-referenced
    struct pl const* const pl
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
 * Translate a pl to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep, // de-referenced
    struct pl const* const pl
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
enum rawrtc_code rawrtc_pl_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
    struct pl const* const pl
);

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
    char const* const str
);

/*
 * Create a new ICE parameters instance.
 * `*parametersp` must be unreferenced.
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
 * `*optionsp` must be unreferenced.
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
 * Create a new ICE gatherer.
 * `*gathererp` must be unreferenced.
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
 */

/*
 * Get the current state of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_state(
    enum rawrtc_ice_gatherer_state* const statep, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer
);

/*
 * Get local ICE parameters of an ICE gatherer.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_parameters(
    struct rawrtc_ice_parameters** const parametersp, // de-referenced
    struct rawrtc_ice_gatherer* const gatherer
);

/*
 * Get local ICE candidates of an ICE gatherer.
 * `*candidatesp` must be unreferenced.
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
 * Get the corresponding name for an ICE gatherer state.
 */
char const * const rawrtc_ice_gatherer_state_to_name(
    enum rawrtc_ice_gatherer_state const state
);

/*
 * Create a new ICE transport.
 * `*transportp` must be unreferenced.
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
char const * const rawrtc_ice_transport_state_to_name(
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

/*
 * Create a new DTLS fingerprint instance.
 * `*fingerprintp` must be unreferenced.
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
 * `*parametersp` must be unreferenced.
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
 * Create a new DTLS transport.
 * `*transport` must be unreferenced.
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
 */

/*
 * Get the current state of the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_get_state(
    enum rawrtc_dtls_transport_state* const statep, // de-referenced
    struct rawrtc_dtls_transport* const transport
);

/*
 * Get local DTLS parameters of a transport.
 * `*parametersp` must be unreferenced.
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

/*
* Get the corresponding name for an ICE transport state.
*/
char const * const rawrtc_dtls_transport_state_to_name(
    enum rawrtc_dtls_transport_state const state
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
 * Create an SCTP transport.
 * `*transportp` must be unreferenced.
 */
enum rawrtc_code rawrtc_sctp_transport_create(
    struct rawrtc_sctp_transport** const transportp, // de-referenced
    struct rawrtc_dtls_transport* const dtls_transport, // referenced
    uint16_t const port, // zeroable
    rawrtc_data_channel_handler* const data_channel_handler, // nullable
    rawrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
    void* const arg // nullable
);

/*
 * Get the corresponding name for a signaling state.
 */
char const * const rawrtc_signaling_state_to_name(
    enum rawrtc_signaling_state const state
);

/*
 * Get the corresponding name for a peer connection state.
 */
char const * const rawrtc_peer_connection_state_to_name(
    enum rawrtc_peer_connection_state const state
);

/*
 * Create a new peer connection configuration.
 * `*configurationp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_create(
    struct rawrtc_peer_connection_configuration** const configurationp, // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy
);

/*
 * Add an ICE server to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server(
    struct rawrtc_peer_connection_configuration* const configuration,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

/*
 * Get ICE servers from the peer connection configuration.
 * `*serversp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_ice_servers(
    struct rawrtc_ice_servers** const serversp, // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration
);

/*
 * Add a certificate to the peer connection configuration to be used
 * instead of an ephemerally generated one.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_certificate(
    struct rawrtc_peer_connection_configuration* configuration,
    struct rawrtc_certificate* const certificate // copied
);

/*
 * Get certificates from the peer connection configuration.
 * `*certificatesp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_certificates(
    struct rawrtc_certificates** const certificatesp, // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration
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
 * `*descriptionp` must be unreferenced.
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
 * Create a new ICE candidate from SDP.
 * `*candidatesp` must be unreferenced.
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
 * `*midp` will be set to a copy of the candidate's mid and must be
 * unreferenced.
 *
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
 * `*username_fragmentp` will be set to a copy of the candidate's
 * username fragment and must be unreferenced.
 *
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
 * `*connectionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create(
    struct rawrtc_peer_connection** const connectionp, // de-referenced
    struct rawrtc_peer_connection_configuration* configuration, // referenced
    rawrtc_negotiation_needed_handler* const negotiation_needed_handler, // nullable
    rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler, // nullable
    rawrtc_peer_connection_local_candidate_error_handler* const local_candidate_error_handler, // nullable
    rawrtc_signaling_state_change_handler* const signaling_state_change_handler, // nullable
    rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler, // nullable
    rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler, // nullable
    rawrtc_peer_connection_state_change_handler* const connection_state_change_handler, //nullable
    rawrtc_data_channel_handler* const data_channel_handler, // nullable
    void* const arg // nullable
);

/*
 * Close the peer connection. This will stop all underlying transports
 * and results in a final 'closed' state.
 */
enum rawrtc_code rawrtc_peer_connection_close(
    struct rawrtc_peer_connection* const connection
);

/*
 * Create an offer.
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create_offer(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection,
    bool const ice_restart
);

/*
 * Create an answer.
 * `*descriptionp` must be unreferenced.
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
 * Get local description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no local description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_description(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set and apply the remote description.
 */
enum rawrtc_code rawrtc_peer_connection_set_remote_description(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_description* const description // referenced
);

/*
 * Get remote description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
*/
enum rawrtc_code rawrtc_peer_connection_get_remote_description(
    struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Add an ICE candidate to the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_add_ice_candidate(
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

/*
 * Get the current signalling state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state(
    enum rawrtc_signaling_state* const statep, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Get the current ICE gathering state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state(
    enum rawrtc_ice_gatherer_state* const statep, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Get the current ICE connection state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state(
    enum rawrtc_ice_transport_state* const statep, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Get the current (peer) connection state of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state(
    enum rawrtc_peer_connection_state* const statep, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Get indication whether the remote peer accepts trickled ICE
 * candidates.
 *
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_can_trickle_ice_candidates(
    bool* const can_trickle_ice_candidatesp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Create a data channel on a peer connection.
 * `*channelp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create_data_channel(
    struct rawrtc_data_channel** const channelp, // de-referenced
    struct rawrtc_peer_connection* const connection,
    struct rawrtc_data_channel_parameters* const parameters, // referenced
    rawrtc_data_channel_open_handler* const open_handler, // nullable
    rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    rawrtc_data_channel_error_handler* const error_handler, // nullable
    rawrtc_data_channel_close_handler* const close_handler, // nullable
    rawrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg // nullable
);

/*
 * Unset the handler argument and all handlers of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_unset_handlers(
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's negotiation needed handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_negotiation_needed_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_negotiation_needed_handler* const negotiation_needed_handler // nullable
);

/*
 * Get the peer connection's negotiation needed handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_negotiation_needed_handler(
    rawrtc_negotiation_needed_handler** const negotiation_needed_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's ICE local candidate handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler // nullable
);

/*
 * Get the peer connection's ICE local candidate handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_handler(
    rawrtc_peer_connection_local_candidate_handler** const local_candidate_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's ICE local candidate error handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_error_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_local_candidate_error_handler* const local_candidate_error_handler // nullable
);

/*
 * Get the peer connection's ICE local candidate error handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_error_handler(
    rawrtc_peer_connection_local_candidate_error_handler** const local_candidate_error_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's signaling state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_signaling_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_signaling_state_change_handler* const signaling_state_change_handler // nullable
);

/*
 * Get the peer connection's signaling state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state_change_handler(
    rawrtc_signaling_state_change_handler** const signaling_state_change_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's ice connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_connection_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler // nullable
);

/*
 * Get the peer connection's ice connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state_change_handler(
    rawrtc_ice_transport_state_change_handler** const ice_connection_state_change_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's ice gathering state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_gathering_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler // nullable
);

/*
 * Get the peer connection's ice gathering state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state_change_handler(
    rawrtc_ice_gatherer_state_change_handler** const ice_gathering_state_change_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's (peer) connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_connection_state_change_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_peer_connection_state_change_handler* const connection_state_change_handler // nullable
);

/*
 * Get the peer connection's (peer) connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state_change_handler(
    rawrtc_peer_connection_state_change_handler** const connection_state_change_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);

/*
 * Set the peer connection's data channel handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_data_channel_handler(
    struct rawrtc_peer_connection* const connection,
    rawrtc_data_channel_handler* const data_channel_handler // nullable
);

/*
 * Get the peer connection's data channel handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_data_channel_handler(
    rawrtc_data_channel_handler** const data_channel_handlerp, // de-referenced
    struct rawrtc_peer_connection* const connection
);
