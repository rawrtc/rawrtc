#include "candidate.h"
#include "../ice_candidate/candidate.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Print debug information for an ICE candidate.
 */
int rawrtc_peer_connection_ice_candidate_debug(
        struct re_printf* const pf,
        struct rawrtc_peer_connection_ice_candidate* const candidate
) {
    int err = 0;

    // Check arguments
    if (!candidate) {
        return 0;
    }

    // ORTC ICE candidate
    err |= re_hprintf(pf, "%H", rawrtc_ice_candidate_debug, candidate->candidate);

    // Media line identification tag
    err |= re_hprintf(pf, "    mid=");
    if (candidate->mid) {
        err |= re_hprintf(pf, "\"%s\"\n", candidate->mid);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }

    // Media line index
    err |= re_hprintf(pf, "    media_line_index=");
    if (candidate->media_line_index >= 0 && candidate->media_line_index <= UINT8_MAX) {
        err |= re_hprintf(pf, "%"PRId16"\n", candidate->media_line_index);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }

    // Username fragment
    err |= re_hprintf(pf, "    username_fragment=");
    if (candidate->username_fragment) {
        err |= re_hprintf(pf, "\"%s\"\n", candidate->username_fragment);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }

    // Done
    return err;
}
