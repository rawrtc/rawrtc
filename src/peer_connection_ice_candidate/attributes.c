#include "candidate.h"
#include <rawrtc/ice_candidate.h>
#include <rawrtc/peer_connection_ice_candidate.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

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
) {
    enum rawrtc_code error;
    char* foundation = NULL;
    uint16_t component_id = 1;
    enum rawrtc_ice_protocol protocol;
    char const* protocol_str;
    uint32_t priority;
    char* ip = NULL;
    uint16_t port;
    enum rawrtc_ice_candidate_type type;
    char const* type_str;
    struct mbuf* sdp = NULL;
    char* related_address = NULL;
    uint16_t related_port = 0;
    enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
    char const* tcp_type_str;

    // Check arguments
    if (!sdpp || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get values for mandatory fields
    error = rawrtc_ice_candidate_get_foundation(&foundation, candidate->candidate);
    if (error) {
        goto out;
    }
    // TODO: Get component ID from candidate/gatherer/transport
    error = rawrtc_ice_candidate_get_protocol(&protocol, candidate->candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_priority(&priority, candidate->candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_ip(&ip, candidate->candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_port(&port, candidate->candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_type(&type, candidate->candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_related_address(&related_address, candidate->candidate);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_related_port(&related_port, candidate->candidate);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        goto out;
    }
    protocol_str = rawrtc_ice_protocol_to_str(protocol);
    type_str = rawrtc_ice_candidate_type_to_str(type);

    // Initialise SDP attribute buffer
    sdp = mbuf_alloc(RAWRTC_PEER_CONNECTION_CANDIDATE_DEFAULT_SIZE);
    if (!sdp) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Encode candidate's mandatory fields
    error = rawrtc_error_to_code(mbuf_printf(
            sdp, "candidate:%s %"PRIu16" %s %"PRIu32" %s %"PRIu16" typ %s",
            foundation, component_id, protocol_str, priority, ip, port, type_str));
    if (error) {
        goto out;
    }
    if (related_address) {
        error = rawrtc_error_to_code(mbuf_printf(sdp, " raddr %s", related_address));
        if (error) {
            goto out;
        }
    }
    if (related_port > 0) {
        error = rawrtc_error_to_code(mbuf_printf(sdp, " rport %"PRIu16, related_port));
        if (error) {
            goto out;
        }
    }

    // Get value for 'tcptype' extension field and encode it (if available)
    error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate->candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            tcp_type_str = rawrtc_ice_tcp_candidate_type_to_str(tcp_type);
            mbuf_printf(sdp, " tcptype %s", tcp_type_str);
            break;
        case RAWRTC_CODE_NO_VALUE:
            break;
        default:
            goto out;
    }

    // Copy SDP attribute
    error = rawrtc_sdprintf(sdpp, "%b", sdp->buf, sdp->end);
    if (error) {
        goto out;
    }

    out:
    // Un-reference
    mem_deref(related_address);
    mem_deref(sdp);
    mem_deref(ip);
    mem_deref(foundation);
    return error;
}

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
) {
    // Check arguments
    if (!midp || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy mid (if any)
    if (candidate->mid) {
        return rawrtc_strdup(midp, candidate->mid);
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the media stream line index the ICE candidate is associated to.
 * Return `RAWRTC_CODE_NO_VALUE` in case no media line index has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp_media_line_index(
        uint8_t* const media_line_index, // de-referenced
        struct rawrtc_peer_connection_ice_candidate* const candidate
) {
    // Check arguments
    if (!media_line_index || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set media line index (if any)
    if (candidate->media_line_index >= 0 && candidate->media_line_index <= UINT8_MAX) {
        *media_line_index = (uint8_t) candidate->media_line_index;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

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
) {
    // Check arguments
    if (!username_fragmentp || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy username fragment (if any)
    if (candidate->username_fragment) {
        return rawrtc_strdup(username_fragmentp, candidate->username_fragment);
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the underlying ORTC ICE candidate from the ICE candidate.
 * `*ortc_candidatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_ortc_candidate(
        struct rawrtc_ice_candidate** const ortc_candidatep, // de-referenced
        struct rawrtc_peer_connection_ice_candidate* const candidate
) {
    // Check arguments
    if (!ortc_candidatep || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Reference ORTC ICE candidate
    *ortc_candidatep = mem_ref(candidate->candidate);
    return RAWRTC_CODE_SUCCESS;
}
