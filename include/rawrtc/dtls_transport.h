#pragma once
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_certificate;
struct rawrtc_dtls_parameters;
struct rawrtc_ice_transport;

/*
 * DTLS role.
 */
enum rawrtc_dtls_role {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER,
};

/*
 * DTLS transport state.
 */
enum rawrtc_dtls_transport_state {
    RAWRTC_DTLS_TRANSPORT_STATE_NEW,
    RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING,
    RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED,
    RAWRTC_DTLS_TRANSPORT_STATE_CLOSED,
    RAWRTC_DTLS_TRANSPORT_STATE_FAILED,
};

/*
 * DTLS transport.
 */
struct rawrtc_dtls_transport;

/*
 * DTLS transport state change handler.
 */
typedef void (*rawrtc_dtls_transport_state_change_handler)(
    enum rawrtc_dtls_transport_state const state,
    void* const arg
);

/*
 * DTLS transport error handler.
 */
typedef void (*rawrtc_dtls_transport_error_handler)(
    // TODO: error.message (probably from OpenSSL)
    void* const arg
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
    rawrtc_dtls_transport_state_change_handler const state_change_handler, // nullable
    rawrtc_dtls_transport_error_handler const error_handler, // nullable
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
char const * rawrtc_dtls_transport_state_to_name(
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
