#include <rawrtc.h>
#include "ice_candidate.h"
#include "peer_connection_ice_candidate.h"

static char const sdp_ice_candidate_regex[] =
        "candidate:[^ ]+ [0-9]+ [^ ]+ [0-9]+ [^ ]+ [0-9]+ typ [^ ]+[^]*";
static char const sdp_ice_candidate_related_address_regex[] = "[^]* raddr [^ ]+";
static char const sdp_ice_candidate_related_port_regex[] = "[^]* rport [0-9]+";
static char const sdp_ice_candidate_tcp_type_regex[] = "[^]* tcptype [^ ]+";

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

/*
 * Destructor for an existing peer connection.
 */
static void rawrtc_peer_connection_ice_candidate_destroy(
        void* arg
) {
    struct rawrtc_peer_connection_ice_candidate* const candidate = arg;

    // Un-reference
    mem_deref(candidate->username_fragment);
    mem_deref(candidate->mid);
    mem_deref(candidate->candidate);
}

/*
 * Create a new ICE candidate from an existing (ORTC) ICE candidate.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_from_ortc_candidate(
        struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced
        struct rawrtc_ice_candidate* const ortc_candidate,
        char* const mid, // nullable, referenced
        uint8_t const* const media_line_index, // nullable, copied
        char* const username_fragment // nullable, referenced
) {
    struct rawrtc_peer_connection_ice_candidate* candidate;

    // Ensure either 'mid' or the media line index is present
    if (!mid && !media_line_index) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_peer_connection_ice_candidate_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    candidate->candidate = mem_ref(ortc_candidate);
    candidate->mid = mem_ref(mid);
    candidate->media_line_index = (int16_t) (media_line_index ? *media_line_index : -1);
    candidate->username_fragment = mem_ref(username_fragment);

    // Set pointer & done
    *candidatep = candidate;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create a new ICE candidate from SDP (pl variant).
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_create_internal(
        struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced
        struct pl* const sdp,
        char* const mid, // nullable, referenced
        uint8_t const* const media_line_index, // nullable, copied
        char* const username_fragment // nullable, referenced
) {
    enum rawrtc_code error;
    struct pl optional;
    uint32_t value_u32;

    // Mandatory fields
    struct pl foundation_pl;
    struct pl component_id_pl;
    struct pl protocol_pl;
    struct pl priority_pl;
    struct pl ip_pl;
    struct pl port_pl;
    struct pl type_pl;
    uint32_t priority;
    enum rawrtc_ice_protocol protocol;
    uint16_t port;
    enum rawrtc_ice_candidate_type type;

    // Optional fields
    struct pl related_address_pl = PL_INIT;
    struct pl related_port_pl = PL_INIT;
    struct pl tcp_type_pl = PL_INIT;
    uint16_t related_port = 0;
    enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;

    // (ORTC) ICE candidate
    struct rawrtc_ice_candidate* ortc_candidate;

    // ICE candidate
    struct rawrtc_peer_connection_ice_candidate* candidate;

    // Check arguments
    if (!candidatep || !pl_isset(sdp)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure either 'mid' or the media line index is present
    if (!mid && !media_line_index) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get mandatory ICE candidate fields
    if (re_regex(
            sdp->p, sdp->l, sdp_ice_candidate_regex, &foundation_pl, &component_id_pl,
            &protocol_pl, &priority_pl, &ip_pl, &port_pl, &type_pl, &optional)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get optional ICE candidate fields
    re_regex(
            optional.p, optional.l, sdp_ice_candidate_related_address_regex,
            NULL, &related_address_pl);
    re_regex(optional.p, optional.l, sdp_ice_candidate_related_port_regex, NULL, &related_port_pl);
    re_regex(optional.p, optional.l, sdp_ice_candidate_tcp_type_regex, NULL, &tcp_type_pl);

    // Component ID
    // TODO: Handle
    (void) component_id_pl;

    // Protocol
    error = rawrtc_pl_to_ice_protocol(&protocol, &protocol_pl);
    if (error) {
        return error;
    }

    // Priority
    priority = pl_u32(&priority_pl);

    // Port
    value_u32 = pl_u32(&port_pl);
    if (value_u32 > UINT16_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
    port = (uint16_t) value_u32;

    // Type
    error = rawrtc_pl_to_ice_candidate_type(&type, &type_pl);
    if (error) {
        return error;
    }

    // Related port (if any)
    if (pl_isset(&related_port_pl)) {
        value_u32 = pl_u32(&related_port_pl);
        if (value_u32 > UINT16_MAX) {
            return RAWRTC_CODE_INVALID_ARGUMENT;
        }
        related_port = (uint16_t) value_u32;
    }

    // TCP type (if any)
    if (pl_isset(&tcp_type_pl)) {
        error = rawrtc_pl_to_ice_tcp_candidate_type(&tcp_type, &tcp_type_pl);
        if (error) {
            return error;
        }
    }

    // Create (ORTC) ICE candidate
    error = rawrtc_ice_candidate_create_internal(
            &ortc_candidate, &foundation_pl, priority, &ip_pl, protocol, port, type, tcp_type,
            &related_address_pl, related_port);
    if (error) {
        return error;
    }

    // Create ICE candidate
    error = rawrtc_peer_connection_ice_candidate_from_ortc_candidate(
            &candidate, ortc_candidate, mid, media_line_index, username_fragment);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(ortc_candidate);
    if (!error) {
        // Set pointer & done
        *candidatep = candidate;
    }
    return error;
}

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
) {
    struct pl sdp_pl;
    enum rawrtc_code error;
    char* mid_copy = NULL;
    char* username_fragment_copy = NULL;

    // Check arguments (not checked in the internal function)
    if (!sdp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert SDP str to pl
    pl_set_str(&sdp_pl, sdp);

    // Copy arguments that will be referenced
    if (mid) {
        error = rawrtc_strdup(&mid_copy, mid);
        if (error) {
            goto out;
        }
    }
    if (username_fragment) {
        error = rawrtc_strdup(&username_fragment_copy, username_fragment);
        if (error) {
            goto out;
        }
    }

    // Create ICE candidate
    error = rawrtc_peer_connection_ice_candidate_create_internal(
            candidatep, &sdp_pl, mid_copy, media_line_index, username_fragment_copy);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(username_fragment_copy);
    mem_deref(mid_copy);
    return error;
}

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
            break;
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
