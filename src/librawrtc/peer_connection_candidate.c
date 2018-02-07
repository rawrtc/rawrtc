#include <rawrtc.h>
#include "peer_connection_candidate.h"

#define DEBUG_MODULE "peer-connection-candidate"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Encode the candidate into SDP.
 * `*sdpp` will be set to a copy of the SDP attribute that must be
 * unreferenced.
 *
 * Note: This is equivalent to the `candidate` attribute of the W3C
 *       WebRTC specification's `RTCIceCandidateInit`.
 */
enum rawrtc_code rawrtc_peer_connection_candidate_get_sdp(
        char** const sdpp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
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
    error = rawrtc_ice_candidate_get_foundation(&foundation, candidate);
    if (error) {
        goto out;
    }
    // TODO: Get component ID from candidate/gatherer/transport
    error = rawrtc_ice_candidate_get_protocol(&protocol, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_priority(&priority, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_ip(&ip, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_port(&port, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_type(&type, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_related_address(&related_address, candidate);
    if (error != RAWRTC_CODE_NO_VALUE) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_related_port(&related_port, candidate);
    if (error != RAWRTC_CODE_NO_VALUE) {
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
    error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
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
 * Get the media stream identification tag the candidate is associated to.
 * `*midp` will be set to a copy of the 'mid' field that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_candidate_get_sdp_mid(
        char** const midp, // de-referenced
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!midp || !candidate || !connection || !connection->local_description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Lookup candidate in the SDP and find the associated 'mid' (if any)
    // TODO: Check if the candidate is associated to the connection

    // Copy mid (yeah, 'bundled_mids' is the correct field. It only contains one 'mid' at the
    // moment)
    return rawrtc_strdup(midp, connection->local_description->bundled_mids);
}

/*
 * Get the media stream line index the candidate is associated to.
 */
enum rawrtc_code rawrtc_peer_connection_candidate_get_sdp_media_line_index(
        uint8_t* const media_line_index, // de-referenced
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!media_line_index || !candidate || !connection || !connection->local_description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Lookup candidate in the SDP and find the associated line index
    // TODO: Check if the candidate is associated to the connection

    // Set media line index (only one media line is supported at the moment)
    *media_line_index = 0;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the username fragment the candidate is associated to.
 * `*username_fragmentp` will be set to a copy of the associated
 * username fragment that must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_candidate_get_username_fragment(
        char** const username_fragmentp, // de-referenced
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_peer_connection* const connection
) {
    enum rawrtc_code error;
    struct rawrtc_ice_parameters* ice_parameters;

    // Check arguments
    if (!username_fragmentp || !candidate || !connection || !connection->context.ice_gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check if the candidate is associated to the connection

    // Get ICE parameters of the connection
    error = rawrtc_ice_gatherer_get_local_parameters(
            &ice_parameters, connection->context.ice_gatherer);
    if (error) {
        return error;
    }

    // Get the username fragment of the associated ICE parameters
    // TODO: Store and fetch this value from the candidate itself (?)
    error = rawrtc_ice_parameters_get_username_fragment(username_fragmentp, ice_parameters);
    if (error) {
        goto out;
    }

out:
    // Un-reference & done
    mem_deref(ice_parameters);
    return error;
}
