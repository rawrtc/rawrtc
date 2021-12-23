#include "candidate.h"
#include "../ice_candidate/candidate.h"
#include <rawrtc/ice_candidate.h>
#include <rawrtc/peer_connection_ice_candidate.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

static char const sdp_ice_candidate_regex[] =
    "candidate:[^ ]+ [0-9]+ [^ ]+ [0-9]+ [^ ]+ [0-9]+ typ [^ ]+[^]*";
static char const sdp_ice_candidate_related_address_regex[] = "[^]* raddr [^ ]+";
static char const sdp_ice_candidate_related_port_regex[] = "[^]* rport [0-9]+";
static char const sdp_ice_candidate_tcp_type_regex[] = "[^]* tcptype [^ ]+";

/*
 * Destructor for an existing peer connection.
 */
static void rawrtc_peer_connection_ice_candidate_destroy(void* arg) {
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
    struct rawrtc_peer_connection_ice_candidate** const candidatep,  // de-referenced
    struct rawrtc_ice_candidate* const ortc_candidate,  // nullable
    char* const mid,  // nullable, referenced
    uint8_t const* const media_line_index,  // nullable, copied
    char* const username_fragment  // nullable, referenced
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
    candidate->media_line_index = (int16_t)(media_line_index ? *media_line_index : -1);
    candidate->username_fragment = mem_ref(username_fragment);

    // Set pointer & done
    *candidatep = candidate;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create a new ICE candidate from SDP (pl variant).
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_create_internal(
    struct rawrtc_peer_connection_ice_candidate** const candidatep,  // de-referenced
    struct pl* const sdp,
    char const* const mid,  // nullable, referenced
    uint8_t const* const media_line_index,  // nullable, copied
    char* const username_fragment  // nullable, referenced
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
    if (!candidatep || !sdp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure either 'mid' or the media line index is present
    if (!mid && !media_line_index) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    if (pl_isset(sdp)) {
        // Get mandatory ICE candidate fields
        if (re_regex(
                sdp->p, sdp->l, sdp_ice_candidate_regex, &foundation_pl, &component_id_pl,
                &protocol_pl, &priority_pl, &ip_pl, &port_pl, &type_pl, &optional)) {
            return RAWRTC_CODE_INVALID_ARGUMENT;
        }

        // Get optional ICE candidate fields
        re_regex(
            optional.p, optional.l, sdp_ice_candidate_related_address_regex, NULL,
            &related_address_pl);
        re_regex(
            optional.p, optional.l, sdp_ice_candidate_related_port_regex, NULL, &related_port_pl);
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
    } else {
        ortc_candidate = NULL;
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
    struct rawrtc_peer_connection_ice_candidate** const candidatep,  // de-referenced
    char const* const sdp,
    char const* const mid,  // nullable, copied
    uint8_t const* const media_line_index,  // nullable, copied
    char* const username_fragment  // nullable, copied
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
