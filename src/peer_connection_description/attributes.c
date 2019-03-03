#include "description.h"
#include <rawrtc/peer_connection_description.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

/*
 * Get the SDP type of the description.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp_type(
        enum rawrtc_sdp_type* const typep, // de-referenced
        struct rawrtc_peer_connection_description* const description
) {
    // Check arguments
    if (!typep || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set SDP type
    *typep = description->type;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the SDP of the description.
 * `*sdpp` will be set to a copy of the SDP that must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp(
        char** const sdpp, // de-referenced
        struct rawrtc_peer_connection_description* const description
) {
    // Check arguments
    if (!sdpp || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy SDP
    return rawrtc_sdprintf(sdpp, "%b", description->sdp->buf, description->sdp->end);
}
