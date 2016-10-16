#include <anyrtc.h>
#include "dtls_transport.h"

#define DEBUG_MODULE "dtls-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Let the DTLS transport attach itself to a candidate pair.
 */
enum anyrtc_code anyrtc_dtls_transport_add_candidate_pair(
        struct anyrtc_dtls_transport *const transport,
        struct ice_candpair *const candidate_pair
) {
    // Check arguments
    if (!transport || !candidate_pair) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // TODO: Implement
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
