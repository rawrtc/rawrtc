#include "transport.h"
#include <rawrtc/dtls_transport.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Check for an existing data transport (on top of DTLS).
 */
enum rawrtc_code rawrtc_dtls_transport_have_data_transport(
        bool* const have_data_transportp, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!have_data_transportp || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if a receive handler has been set.
    if (transport->receive_handler) {
        *have_data_transportp = true;
    } else {
        *have_data_transportp = false;
    }
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the current state of the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_get_state(
        enum rawrtc_dtls_transport_state* const statep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state & done
    *statep = transport->state;
    return RAWRTC_CODE_SUCCESS;
}
