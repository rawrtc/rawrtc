#include <rawrtc.h>
#include "peer_connection_description.h"

#define DEBUG_MODULE "peer-connection-description"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

// Constants
static uint16_t const port_bundle_only = 0;
static uint16_t const port_unspecified = 9;

/*
 * Add ICE attributes to SDP media line.
 */
static enum rawrtc_code add_ice_attributes(
        struct sdp_media* const media, // not checked
        struct rawrtc_peer_connection_context* const context // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_ice_parameters* parameters;
    char* username_fragment = NULL;
    char* password = NULL;

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
    error = rawrtc_error_to_code(sdp_media_set_lattr(
            media, false, "ice-ufrag", "%s", username_fragment));
    error |= rawrtc_error_to_code(sdp_media_set_lattr(media, false, "ice-pwd", "%s", password));
    if (error) {
        goto out;
    }

    // TODO: Continue here

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
        struct sdp_media* const media, // not checked
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
        error = rawrtc_error_to_code(sdp_media_set_lattr(
                media, false, "fingerprint", "%s %s",
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
        struct sdp_media* const media, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
        bool const offer
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
    // TODO: Needs to be fixed for answer
    if (offer) {
        // Note: When offering, we MUST use 'actpass' as specified in JSEP
        setup_str = "actpass";
    } else {
        setup_str = "TODO";
    }
//    switch (role) {
//        case RAWRTC_DTLS_ROLE_AUTO:
//            setup_str = "actpass";
//            break;
//        case RAWRTC_DTLS_ROLE_CLIENT:
//            setup_str = "active";
//            break;
//        case RAWRTC_DTLS_ROLE_SERVER:
//            setup_str = "passive";
//            break;
//        default:
//            error = RAWRTC_CODE_INVALID_STATE;
//            goto out;
//            break;
//    }
    error = rawrtc_error_to_code(sdp_media_set_lattr(media, false, "setup", setup_str));
    if (error) {
        goto out;
    }

    // Add fingerprints
    error = add_dtls_fingerprint_attributes(media, parameters);
    if (error) {
        goto out;
    }

    // Add DTLS ID
    error = rawrtc_error_to_code(sdp_media_set_lattr(
            media, false, "dtls-id", "%s", context->dtls_id));
    if (error) {
        goto out;
    }

    out:
    mem_deref(parameters);
    return error;
}

/*
 * Add common attributes to SDP media line.
 */
static enum rawrtc_code add_common_attributes(
        struct sdp_media* const media, // not checked
        char const* const mid,
        bool const bundle_only
) {
    struct sa address;
    enum rawrtc_code error;

    // Sanity-check
    if (!mid && bundle_only) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Use IPv4 unspecified as media address
    sa_set_in(&address, INADDR_ANY, bundle_only ? port_bundle_only : port_unspecified);
    sdp_media_set_laddr(media, &address);

    // Add identification tag attribute (if required)
    if (mid) {
        error = rawrtc_error_to_code(sdp_media_set_lattr(
                media, false, "mid", "%s", mid));
        if (error) {
            return error;
        }
    }

    // Add bundle-only attribute (if required)
    if (bundle_only) {
        error = rawrtc_error_to_code(sdp_media_set_lattr(media, false, "bundle-only", NULL, NULL));
        if (error) {
            return error;
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add SCTP data channel media line to SDP session.
 */
enum rawrtc_code add_sctp_data_channel(
        struct sdp_session* const session,
        struct rawrtc_peer_connection_context* const context,
        char const* const mid,
        bool const offer,
        bool const bundle_only,
        bool const sctp_sdp_06
) {
    struct rawrtc_sctp_transport* const transport = context->data_transport->transport;
    char const* const application = "webrtc-datachannel";
    uint_fast8_t const maximum_message_size = 0;
    enum rawrtc_code error;
    uint16_t sctp_port;
    char const* protocol_str;
    struct sdp_media* media = NULL;
    char* format_str = NULL;
    struct sdp_format* format = NULL;

    // Check arguments
    if (!session || !context) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get SCTP port
    error = rawrtc_sctp_transport_get_port(&sctp_port, transport);
    if (error) {
        goto out;
    }

    // Media section
    // Note: We choose UDP here although communication may still happen over ICE-TCP candidates.
    // See also: https://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-25#section-12.2
    protocol_str = sctp_sdp_06 ? "DTLS/SCTP" : "UDP/DTLS/SCTP";
    error = rawrtc_error_to_code(sdp_media_add(
            &media, session, "application", port_unspecified, protocol_str));
    if (error) {
        goto out;
    }

    // Don't set direction attribute
    sdp_media_ldir_exclude(media, true);

    // Prepare format string
    if (sctp_sdp_06) {
        error = rawrtc_sdprintf(&format_str, "%"PRIu16, sctp_port);
        if (error) {
            goto out;
        }
    }

    // Add format
    error = rawrtc_error_to_code(sdp_format_add(
            &format, media, false, format_str ? format_str : application,
            NULL, 0, 0, NULL, NULL, NULL, false, ""));
    mem_deref(format_str);
    if (error) {
        goto out;
    }

    // Add common attributes
    error = add_common_attributes(media, mid, bundle_only);
    if (error) {
        goto out;
    }

    // Set attributes
    if (!sctp_sdp_06) {
        // Set SCTP port
        error = rawrtc_error_to_code(sdp_media_set_lattr(
                media, false, "sctp-port", "%"PRIu16, sctp_port));

        // Set maximum message size
        error |= rawrtc_error_to_code(sdp_media_set_lattr(
                media, false, "maximum-message-size", "%"PRIuFAST8, maximum_message_size));

        // Handle error
        if (error) {
            goto out;
        }
    } else {
        // Set SCTP port and maximum message size
        // Note: We don't set the #streams as the newest DCEP spec says it MUST be set to the
        //       maximum amount of streams, so this is not negotiable.
        error = rawrtc_error_to_code(sdp_media_set_lattr(
                media, false, "sctpmap", "%"PRIu16" %s %"PRIuFAST8, sctp_port, application,
                maximum_message_size));
        if (error) {
            goto out;
        }
    }

    // Add upper-layer attributes (if not bundled)
    if (!bundle_only) {
        // Add DTLS attributes
        error = add_dtls_attributes(media, context, offer);
        if (error) {
            goto out;
        }

        // Add ICE attributes
        error = add_ice_attributes(media, context);
        if (error) {
            goto out;
        }
    }

    out:
    if (error) {
        mem_deref(format);
        mem_deref(media);
    }
    // TODO: Set media on some kind of offer context
    return error;
}

/*
 * Set session attributes on SDP.
 */
static enum rawrtc_code set_session_attributes(
        struct sdp_session* const session,
        char const* const mids
) {
    int err;

    // Check arguments
    if (!session || !mids) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Trickle ICE
    err = sdp_session_set_lattr(session, false, "ice-options", "trickle");

    // WebRTC Identity
    // (N/A)

    // Bundle media (we currently only support a single SCTP transport)
    err |= sdp_session_set_lattr(session, false, "group", "BUNDLE %s", mids);

    // Done
    return rawrtc_error_to_code(err);
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
    list_flush(&description->media);
    mem_deref(description->session);
}

/*
 * Create a new description.
 */
enum rawrtc_code rawrtc_peer_connection_description_create(
        struct rawrtc_peer_connection_description** const descriptionp,
        struct rawrtc_peer_connection_context* const context
) {
    struct rawrtc_peer_connection_description* description;
    struct sa address;
    enum rawrtc_code error;
    char const* const mid = "rawrtc-sctp-dc";
    bool bundle_only = false;
    bool const sctp_sdp_06 = true; // TODO: Get from config

    // Check arguments
    if (!descriptionp || !context) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    description = mem_zalloc(sizeof(*description), rawrtc_peer_connection_description_destroy);
    if (!description) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Create SDP session (use IPv4 unspecified as session address)
    sa_set_in(&address, INADDR_ANY, 0);
    error = rawrtc_error_to_code(sdp_session_alloc(&description->session, &address));
    if (error) {
        goto out;
    }

    // Session attributes
    error = set_session_attributes(description->session, mid);
    if (error) {
        goto out;
    }

    // Add data transport (if any)
    if (context->dtls_transport && context->data_transport) {
        switch (context->data_transport->type) {
            case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
                // Add SCTP transport
                error = add_sctp_data_channel(
                        description->session, context, mid, true, bundle_only, sctp_sdp_06);
                if (error) {
                    goto out;
                }

                // Bundle further media
                bundle_only = true;
                break;
            default:
                error = RAWRTC_CODE_UNKNOWN_ERROR;
                goto out;
                break;
        }
    }

    // Encode SDP
    error = rawrtc_error_to_code(sdp_encode(&description->sdp, description->session, true));
    if (error) {
        goto out;
    }

    // Debug
    (void) bundle_only;
    DEBUG_PRINTF("Description:\n%b", mbuf_buf(description->sdp), mbuf_get_left(description->sdp));
    DEBUG_PRINTF("%H\n", sdp_session_debug, description->session);

    // Set fields/reference
    // TODO

out:
    if (error) {
        mem_deref(description);
    } else {
        // Set pointer & done
        *descriptionp = description;
    }
    return error;
}
