#include <rawrtc.h>
#include "peer_connection_description.h"

#define DEBUG_MODULE "peer-connection-description"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

// Constants
static uint16_t const discard_port = 9;

/*
 * Set session boilerplate
 */
static enum rawrtc_code set_session_boilerplate(
        struct mbuf* const sdp, // not checked
        char const* const version, // not checked
        uint32_t const id
) {
    int err;

    // Write session boilerplate
    err = mbuf_write_str(sdp, "v=0\r\n");
    err |= mbuf_printf(
            sdp, "o=sdpartanic-rawrtc-%s %"PRIu32" 1 IN IP4 127.0.0.1\r\n", version, id);
    err |= mbuf_write_str(sdp, "s=-\r\n");
    err |= mbuf_write_str(sdp, "t=0 0\r\n");

    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Set session attributes on SDP.
 */
static enum rawrtc_code set_session_attributes(
        struct mbuf* const sdp, // not checked
        bool const trickle_ice,
        char const* const bundled_mids
) {
    int err = 0;

    // Trickle ICE
    if (trickle_ice) {
        err = mbuf_write_str(sdp, "a=ice-options:trickle\r\n");
    }

    // WebRTC identity not supported as of now

    // Bundle media (we currently only support a single SCTP transport and nothing else)
    if (bundled_mids) {
        err |= mbuf_printf(sdp, "a=group:BUNDLE %s\r\n", bundled_mids);
    }

    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Add ICE attributes to SDP media line.
 */
static enum rawrtc_code add_ice_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_peer_connection_context* const context // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_ice_parameters* parameters;
    char* username_fragment = NULL;
    char* password = NULL;
    int err;

    // Get ICE parameters
    error = rawrtc_ice_gatherer_get_local_parameters(&parameters, context->ice_gatherer);
    if (error) {
        return error;
    }

    // Get values
    error = rawrtc_ice_parameters_get_username_fragment(&username_fragment, parameters);
    error |= rawrtc_ice_parameters_get_password(&password, parameters);
    if (error) {
        goto out;
    }

    // Set username fragment and password
    err = mbuf_printf(sdp, "a=ice-ufrag:%s\r\n", username_fragment);
    err |= mbuf_printf(sdp, "a=ice-pwd:%s\r\n", password);
    error = rawrtc_error_to_code(err);

out:
    mem_deref(password);
    mem_deref(username_fragment);
    mem_deref(parameters);
    return error;
}

/*
 * Add DTLS fingerprint attributes to SDP media line.
 */
static enum rawrtc_code add_dtls_fingerprint_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_dtls_parameters* const parameters // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;

    // Get fingerprints
    error = rawrtc_dtls_parameters_get_fingerprints(&fingerprints, parameters);
    if (error) {
        return error;
    }

    // Add fingerprints
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint = fingerprints->fingerprints[i];
        enum rawrtc_certificate_sign_algorithm sign_algorithm;
        char* value;

        // Get sign algorithm and fingerprint value
        error = rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(&sign_algorithm, fingerprint);
        error |= rawrtc_dtls_parameters_fingerprint_get_value(&value, fingerprint);
        if (error) {
            goto out;
        }

        // Add fingerprint attribute
        error = rawrtc_error_to_code(mbuf_printf(
                sdp, "a=fingerprint:%s %s\r\n",
                rawrtc_certificate_sign_algorithm_to_str(sign_algorithm), value));
        if (error) {
            goto out;
        }
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    mem_deref(fingerprints);
    return error;
}

/*
 * Add DTLS transport attributes to SDP media line.
 */
static enum rawrtc_code add_dtls_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
        bool const offerer
) {
    enum rawrtc_code error;
    struct rawrtc_dtls_parameters* parameters;
    enum rawrtc_dtls_role role;
    char const* setup_str;

    // Get DTLS parameters
    error = rawrtc_dtls_transport_get_local_parameters(&parameters, context->dtls_transport);
    if (error) {
        return error;
    }

    // Get DTLS role
    error = rawrtc_dtls_parameters_get_role(&role, parameters);
    if (error) {
        goto out;
    }

    // Add setup attribute
    if (offerer) {
        // Note: When offering, we MUST use 'actpass' as specified in JSEP
        setup_str = "actpass";
    } else {
        switch (role) {
            case RAWRTC_DTLS_ROLE_AUTO:
                setup_str = "active";
                break;
            case RAWRTC_DTLS_ROLE_CLIENT:
                setup_str = "active";
                break;
            case RAWRTC_DTLS_ROLE_SERVER:
                setup_str = "passive";
                break;
            default:
                error = RAWRTC_CODE_INVALID_STATE;
                goto out;
                break;
        }
    }
    error = rawrtc_error_to_code(mbuf_printf(sdp, "a=setup:%s\r\n", setup_str));
    if (error) {
        goto out;
    }

    // Add fingerprints
    error = add_dtls_fingerprint_attributes(sdp, parameters);
    if (error) {
        goto out;
    }

    // Add (D)TLS ID
    error = rawrtc_error_to_code(mbuf_printf(sdp, "a=tls-id:%s\r\n", context->dtls_id));
    if (error) {
        goto out;
    }

out:
    mem_deref(parameters);
    return error;
}

/*
 * Add SCTP data transport media line to SDP session.
 */
static enum rawrtc_code add_sctp_data_transport(
        struct mbuf* const sdp, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
        bool const offerer,
        char const* const remote_media_line,
        char const* const mid, // not checked
        bool const sctp_sdp_05
) {
    struct rawrtc_sctp_transport* const transport = context->data_transport->transport;
    enum rawrtc_code error;
    uint16_t sctp_port;
    int err;

    // Get SCTP port
    error = rawrtc_sctp_transport_get_port(&sctp_port, transport);
    if (error) {
        return error;
    }

    // Add media section
    if (remote_media_line) {
        // Just repeat the remote media line.
        err = mbuf_write_str(sdp, remote_media_line);
    } else {
        if (!sctp_sdp_05) {
            // Note: We choose UDP here although communication may still happen over ICE-TCP
            //       candidates.
            // See also: https://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-25#section-12.2
            err = mbuf_printf(
                    sdp, "m=application %"PRIu16" UDP/DTLS/SCTP webrtc-datachannel\r\n",
                    discard_port);
        } else {
            err = mbuf_printf(
                    sdp, "m=application %"PRIu16" DTLS/SCTP %"PRIu16"\r\n",
                    discard_port, sctp_port);
        }
    }
    // Add dummy 'c'-line
    err |= mbuf_write_str(sdp, "c=IN IP4 0.0.0.0\r\n");
    // Add 'mid' line
    err |= mbuf_printf(sdp, "a=mid:%s\r\n", mid);
    // Add direction line
    err |= mbuf_write_str(sdp, "a=sendrecv\r\n");
    if (err) {
        return rawrtc_error_to_code(err);
    }

    // Add ICE attributes
    error = add_ice_attributes(sdp, context);
    if (error) {
        return error;
    }

    // Add DTLS attributes
    error = add_dtls_attributes(sdp, context, offerer);
    if (error) {
        return error;
    }

    // Set attributes
    if (!sctp_sdp_05) {
        // Set SCTP port
        // Note: Last time I checked, Chrome wasn't able to cope with this
        err = mbuf_printf(sdp, "a=sctp-port:%"PRIu16"\r\n", sctp_port);
    } else {
        // Set SCTP port, upper layer protocol and number of streams
        err = mbuf_printf(
                sdp, "a=sctpmap:%"PRIu16" webrtc-datachannel 65535\r\n",
                sctp_port);
    }
    if (err) {
        return rawrtc_error_to_code(err);
    }

    // Set maximum message size
    // Note: This isn't part of the 05 version but Firefox can only parse 'max-message-size' but
    //       doesn't understand the old 'sctpmap' one (from 06 to 21).
    err = mbuf_write_str(sdp, "a=max-message-size:0\r\n");
    error = rawrtc_error_to_code(err);
    if (error) {
        return error;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing peer connection description.
 */
static void rawrtc_peer_connection_description_destroy(
        void* arg
) {
    struct rawrtc_peer_connection_description* const description = arg;

    // Un-reference
    mem_deref(description->sdp);
    mem_deref(description->remote_media_line);
    mem_deref(description->bundled_mids);
    mem_deref(description->connection);
}

/*
 * Create a description by creating an offer or answer.
 */
enum rawrtc_code rawrtc_peer_connection_description_create_internal(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection,
        bool const offerer
) {
    struct rawrtc_peer_connection_context* context;
    struct rawrtc_peer_connection_description* local_description;
    struct rawrtc_peer_connection_description* remote_description;
    struct mbuf* sdp = NULL;
    enum rawrtc_code error;

    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get context
    context = &connection->context;

    // Ensure a data transport has been set (when offering)
    if (offerer && !context->data_transport) {
        DEBUG_WARNING("No data transport set\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure a remote description is available (when answering)
    remote_description = connection->remote_description;
    if (!offerer && !remote_description) {
        DEBUG_WARNING("No remote description set\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Create a more sophisticated SDP mechanism based on
    //       https://github.com/nils-ohlmeier/rsdparsa

    // Allocate
    local_description = mem_zalloc(
            sizeof(*local_description), rawrtc_peer_connection_description_destroy);
    if (!local_description) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Set initial values
    if (offerer) {
        local_description->connection = mem_ref(connection); // TODO: Possible circular reference
        local_description->type = RAWRTC_SDP_TYPE_OFFER;
        local_description->trickle_ice = true;
        local_description->sctp_sdp_05 = connection->configuration->sctp_sdp_05;
        error = rawrtc_strdup(
                &local_description->bundled_mids, RAWRTC_PEER_CONNECTION_DESCRIPTION_MID);
        if (error) {
            goto out;
        }
    } else {
        local_description->type = RAWRTC_SDP_TYPE_ANSWER;
        local_description->trickle_ice = remote_description->trickle_ice;
        local_description->bundled_mids = mem_ref(remote_description->bundled_mids);
        local_description->remote_media_line = mem_ref(remote_description->remote_media_line);
        local_description->sctp_sdp_05 = remote_description->sctp_sdp_05;
    }

    // Create buffer for local description
    sdp = mbuf_alloc(RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SIZE);
    if (!sdp) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Set session boilerplate
    error = set_session_boilerplate(sdp, RAWRTC_VERSION, rand_u32());
    if (error) {
        goto out;
    }

    // Set session attributes
    error = set_session_attributes(
            sdp, local_description->trickle_ice, local_description->bundled_mids);
    if (error) {
        goto out;
    }

    // Add data transport (if any)
    switch (context->data_transport->type) {
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
            // Add SCTP transport
            error = add_sctp_data_transport(
                    sdp, context, true, local_description->remote_media_line,
                    local_description->bundled_mids, local_description->sctp_sdp_05);
            if (error) {
                goto out;
            }
            break;
        default:
            error = RAWRTC_CODE_UNKNOWN_ERROR;
            goto out;
            break;
    }

    // Debug
    DEBUG_PRINTF(
            "Local description (%s):\n%b",
            offerer ? "offer" : "answer",
            mbuf_buf(local_description->sdp), mbuf_get_left(local_description->sdp));

    // Reference SDP
    local_description->sdp = mem_ref(sdp);

out:
    mem_deref(sdp);
    if (error) {
        mem_deref(local_description);
    } else {
        // Set pointer & done
        *descriptionp = local_description;
    }
    return error;
}

/*
 * Create a description by parsing an offer or answer.
 */
enum rawrtc_code rawrtc_peer_connection_description_create(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection,
        bool const offerer
) {
    /*
     * TODO: Parse remote description.
     * - only accept 'offer' or 'answer'
     * - amount of m-lines must be 1 for us
     * - if offer not bundled, just don't bundle either
     * - fallback: get stuff from session level if not in media line
     * - create a data transport if it's not created
     * - return NO_VALUE if nothing to do
     */

    // Decode SDP
    // TODO: Fix me
    error = rawrtc_error_to_code(sdp_decode(session, description, true));
    if (error) {
        goto out;
    }

    // Debug
    DEBUG_PRINTF("Remote description:\n%b", mbuf_buf(description), mbuf_get_left(description));
    DEBUG_PRINTF("%H\n", sdp_session_debug, connection->sdp_session);
}

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
    return rawrtc_sdprintf(sdpp, "%b", mbuf_buf(description->sdp), mbuf_get_left(description->sdp));
}
