#include "transport.h"
#include <rawrtc/dtls_transport.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/external.h>

/*
 * Get external DTLS role.
 */
enum rawrtc_code rawrtc_dtls_transport_get_external_role(
        enum rawrtc_external_dtls_role* const rolep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!rolep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert role
    switch (transport->role) {
        case RAWRTC_DTLS_ROLE_AUTO:
            // Unable to convert in this state
            return RAWRTC_CODE_INVALID_STATE;
        case RAWRTC_DTLS_ROLE_CLIENT:
            *rolep = RAWRTC_EXTERNAL_DTLS_ROLE_CLIENT;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_ROLE_SERVER:
            *rolep = RAWRTC_EXTERNAL_DTLS_ROLE_SERVER;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }
}

/*
 * Convert DTLS transport state to external DTLS transport state.
 */
enum rawrtc_code rawrtc_dtls_transport_get_external_state(
        enum rawrtc_external_dtls_transport_state* const statep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert DTLS transport state to external DTLS transport state
    switch (transport->state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_NEW:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_NEW_OR_CONNECTING;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_NEW_OR_CONNECTING;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CONNECTED;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CLOSED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CLOSED_OR_FAILED;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CLOSED_OR_FAILED;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }
}
