#include "description.h"
#include "../dtls_parameters/parameters.h"
#include "../ice_parameters/parameters.h"
#include "../peer_connection_ice_candidate/candidate.h"
#include <rawrtc/peer_connection_description.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/sctp_capabilities.h>
#include <re.h>

static enum rawrtc_sdp_type const map_enum_sdp_type[] = {
    RAWRTC_SDP_TYPE_OFFER,
    RAWRTC_SDP_TYPE_PROVISIONAL_ANSWER,
    RAWRTC_SDP_TYPE_ANSWER,
    RAWRTC_SDP_TYPE_ROLLBACK,
};

static char const * const map_str_sdp_type[] = {
    "offer",
    "pranswer",
    "answer",
    "rollback",
};

static size_t const map_sdp_type_length =
    ARRAY_SIZE(map_enum_sdp_type);

/*
 * Translate an SDP type to str.
 */
char const * rawrtc_sdp_type_to_str(
        enum rawrtc_sdp_type const type
) {
    size_t i;

    for (i = 0; i < map_sdp_type_length; ++i) {
        if (map_enum_sdp_type[i] == type) {
            return map_str_sdp_type[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an SDP type.
 */
enum rawrtc_code rawrtc_str_to_sdp_type(
        enum rawrtc_sdp_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_sdp_type_length; ++i) {
        if (str_casecmp(map_str_sdp_type[i], str) == 0) {
            *typep = map_enum_sdp_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Print debug information for a peer connection description.
 */
int rawrtc_peer_connection_description_debug(
        struct re_printf* const pf,
        struct rawrtc_peer_connection_description* const description
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!description) {
        return 0;
    }

    err |= re_hprintf(pf, "----- Peer Connection Description <%p>\n", description);

    // Print general fields
    err |= re_hprintf(pf, "  peer_connection=");
    if (description->connection) {
        err |= re_hprintf(pf, "%p\n", description->connection);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  sdp_type=%s\n", rawrtc_sdp_type_to_str(description->type));
    err |= re_hprintf(pf, "  trickle_ice=%s\n", description->trickle_ice ? "yes" : "no");
    err |= re_hprintf(pf, "  bundled_mids=");
    if (description->bundled_mids) {
        err |= re_hprintf(pf, "\"%s\"\n", description->bundled_mids);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  remote_media_line=");
    if (description->remote_media_line) {
        err |= re_hprintf(pf, "\"%s\"\n", description->remote_media_line);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  media_line_index=%"PRIu8"\n", description->media_line_index);
    err |= re_hprintf(pf, "  mid=");
    if (description->mid) {
        err |= re_hprintf(pf, "\"%s\"\n", description->mid);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  sctp_sdp_05=%s\n", description->sctp_sdp_05 ? "yes" : "no");
    err |= re_hprintf(
            pf, "  end_of_candidates=%s\n", description->end_of_candidates ? "yes" : "no");

    // Print ICE parameters
    if (description->ice_parameters) {
        err |= re_hprintf(pf, "%H", rawrtc_ice_parameters_debug, description->ice_parameters);
    } else {
        err |= re_hprintf(pf, "  ICE Parameters <n/a>\n");
    }

    // Print ICE candidates
    le = list_head(&description->ice_candidates);
    if (le) {
        for (; le != NULL; le = le->next) {
            struct rawrtc_peer_connection_ice_candidate *const candidate = le->data;
            err |= re_hprintf(pf, "%H", rawrtc_peer_connection_ice_candidate_debug, candidate);
        }
    } else {
        err |= re_hprintf(pf, "  ICE Candidates <n/a>\n");
    }

    // Print DTLS parameters
    if (description->dtls_parameters) {
        err |= re_hprintf(pf, "%H", rawrtc_dtls_parameters_debug, description->dtls_parameters);
    } else {
        err |= re_hprintf(pf, "  DTLS Parameters <n/a>\n");
    }

    // Print SCTP capabilities & port
    if (description->sctp_capabilities) {
        err |= re_hprintf(pf, "%H", rawrtc_sctp_capabilities_debug, description->sctp_capabilities);
    } else {
        err |= re_hprintf(pf, "  SCTP Capabilities <n/a>\n");
    }
    err |= re_hprintf(
            pf, "  sctp_port=%"PRIu16"\n", description->sctp_port);

    // Print SDP
    err |= re_hprintf(pf, "  sdp=\n%b", description->sdp->buf, description->sdp->end);

    // Done
    return err;
}
