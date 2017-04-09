#include <string.h> // memcpy
#include <rawrtc.h>
#include "certificate.h"
#include "dtls_transport.h"
#include "peer_connection.h"

#define DEBUG_MODULE "peer-connection"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

// Constants
uint16_t const port_bundle_only = 0;
uint16_t const port_unspecified = 9;

/*
 * Get the corresponding name for a peer connection state.
 */
char const * const rawrtc_peer_connection_state_to_name(
        enum rawrtc_peer_connection_state const state
) {
    switch (state) {
        case RAWRTC_PEER_CONNECTION_STATE_NEW:
            return "new";
        case RAWRTC_PEER_CONNECTION_STATE_CONNECTING:
            return "connecting";
        case RAWRTC_PEER_CONNECTION_STATE_CONNECTED:
            return "connected";
        case RAWRTC_PEER_CONNECTION_STATE_DISCONNECTED:
            return "disconnected";
        case RAWRTC_PEER_CONNECTION_STATE_CLOSED:
            return "closed";
        case RAWRTC_PEER_CONNECTION_STATE_FAILED:
            return "failed";
        default:
            return "???";
    }
}

/*
 * Remove all instances that have been created which are not
 * associated to the peer connection.
 */
static void revert_context(
        struct rawrtc_peer_connection_context* const new,
        struct rawrtc_peer_connection_context* const current
) {
    if (new->data_transport != current->data_transport) {
        mem_deref(new->data_transport);
    }
    if (new->dtls_transport != current->dtls_transport) {
        mem_deref(new->dtls_transport);
    }
    if (!list_isempty(&new->certificates) && list_isempty(&current->certificates)) {
        list_flush(&new->certificates);
    }
    if (new->ice_transport != current->ice_transport) {
        mem_deref(new->ice_transport);
    }
    if (new->ice_gatherer != current->ice_gatherer) {
        mem_deref(new->ice_gatherer);
    }
}

/*
 * Apply all instances on a peer connection.
 */
static void apply_context(
        struct rawrtc_peer_connection* connection, // not checked
        struct rawrtc_peer_connection_context* const context // de-referenced, not checked
) {
    // Store new context
    connection->context = *context;
}

void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url,
        void* const arg
) {
    (void) candidate; (void) arg;
    DEBUG_WARNING("HANDLE ICE gatherer local candidate, URL: %s\n", url);
}

void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate,
        char const * const url,
        uint16_t const error_code,
        char const * const error_text,
        void* const arg
) {
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_WARNING("HANDLE ICE gatherer error, URL: %s, reason: %s\n", url, error_text);
}

void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state,
        void* const arg
) {
    (void) arg;
    DEBUG_WARNING("HANDLE ICE gatherer state: %s\n", rawrtc_ice_gatherer_state_to_name(state));
}

/*
 * Lazy-create an ICE gatherer.
 */
static enum rawrtc_code get_ice_gatherer(
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    // Already created?
    if (context->ice_gatherer) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Create ICE gatherer
    return rawrtc_ice_gatherer_create(
            &context->ice_gatherer, connection->gather_options, ice_gatherer_state_change_handler,
            ice_gatherer_error_handler, ice_gatherer_local_candidate_handler, connection);
}

static void ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg // will be casted to `struct client*`
) {
    // TODO
    (void) local; (void) remote; (void) arg;
    DEBUG_WARNING("HANDLE ICE candidate pair change\n");
}

static void ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg
) {
    // TODO
    (void) arg;
    DEBUG_WARNING("HANDLE ICE transport state: %s\n", rawrtc_ice_transport_state_to_name(state));
}

/*
 * Lazy-create an ICE transport.
 */
static enum rawrtc_code get_ice_transport(
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;

    // Already created?
    if (context->ice_transport) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Get ICE gatherer
    error = get_ice_gatherer(context, connection);
    if (error) {
        return error;
    }

    // Create ICE transport
    return rawrtc_ice_transport_create(
            &context->ice_transport, context->ice_gatherer, ice_transport_state_change_handler,
            ice_transport_candidate_pair_change_handler, connection);
}

/*
 * Lazy-generate a certificate list.
 */
static enum rawrtc_code get_certificates(
        struct rawrtc_peer_connection_context* const context // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_certificate* certificate;

    // Already created?
    if (!list_isempty(&context->certificates)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Generate a certificate
    // TODO: Apply options from peer connection options
    error = rawrtc_certificate_generate(&certificate, NULL);
    if (error) {
        return error;
    }

    // Add certificate to the list
    list_append(&context->certificates, &certificate->le, certificate);
    return RAWRTC_CODE_SUCCESS;
}

static void dtls_transport_error_handler(
        void* const arg
) {
    // TODO
    (void) arg;
    DEBUG_WARNING("HANDLE DTLS transport error\n");
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state,
        void* const arg
) {
    struct rawrtc_peer_connection* connection = arg;

    // Update connection state
    // TODO: Handle correctly
    switch (state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_CONNECTING;
            break;
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_CONNECTED;
            break;
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_FAILED;
            break;
        default:
            break;
    }
    DEBUG_WARNING("HANDLE DTLS transport state: %s\n",
                  rawrtc_dtls_transport_state_to_name(state));
}

/*
 * Lazy-create a DTLS transport.
 */
static enum rawrtc_code get_dtls_transport(
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;
    struct list certificates = LIST_INIT;

    // Already created?
    if (context->dtls_transport) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Get ICE transport
    error = get_ice_transport(context, connection);
    if (error) {
        return error;
    }

    // Get certificates
    error = get_certificates(context);
    if (error) {
        return error;
    }

    // Copy certificates list
    error = rawrtc_certificate_list_copy(&certificates, &context->certificates);
    if (error) {
        return error;
    }

    // Generate random DTLS ID
    rand_str(context->dtls_id, sizeof(context->dtls_id));

    // Create DTLS transport
    return rawrtc_dtls_transport_create_internal(
            &context->dtls_transport, context->ice_transport, &certificates,
            dtls_transport_state_change_handler, dtls_transport_error_handler, connection);
}

static void sctp_transport_state_change_handler(
        enum rawrtc_sctp_transport_state const state,
        void* const arg
) {
    // TODO
    (void) arg;
    DEBUG_WARNING("HANDLE SCTP transport state: %s\n",
                  rawrtc_sctp_transport_state_to_name(state));
}

/*
 * Lazy-create the requested data transport.
 */
static enum rawrtc_code get_data_transport(
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;

    // Already created?
    if (context->data_transport) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Create data transport depending on what we want to have
    switch (connection->data_transport_type) {
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
            {
                struct rawrtc_sctp_transport* sctp_transport;

                // Get DTLS transport
                error = get_dtls_transport(context, connection);
                if (error) {
                    return error;
                }

                // Create SCTP transport
                error = rawrtc_sctp_transport_create(
                        &sctp_transport, context->dtls_transport,
                        RAWRTC_PEER_CONNECTION_SCTP_TRANSPORT_PORT,
                        connection->data_channel_handler, sctp_transport_state_change_handler,
                        connection);
                if (error) {
                    return error;
                }

                // Get data transport
                error = rawrtc_sctp_transport_get_data_transport(
                        &context->data_transport, sctp_transport);
                if (error) {
                    mem_deref(sctp_transport);
                    return error;
                }
            }

            break;
        default:
            return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing peer connection.
 */
static void rawrtc_peer_connection_destroy(
        void* arg
) {
    struct rawrtc_peer_connection* const connection = arg;

    // Close peer connection
//    rawrtc_peer_connection_close(connection);

    // Un-reference
    mem_deref(connection->context.data_transport);
    mem_deref(connection->context.dtls_transport);
    list_flush(&connection->context.certificates);
    mem_deref(connection->context.ice_transport);
    mem_deref(connection->context.ice_gatherer);
    mem_deref(connection->sdp_session);
    mem_deref(connection->gather_options);
}

/*
 * Create a new peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create(
        struct rawrtc_peer_connection** const connectionp, // de-referenced
//        rawrtc_peer_connection_negotiation_needed_handler* const negotiation_needed_handler, // nullable
//        rawrtc_peer_connection_ice_candidate_handler* const ice_candidate_handler, // nullable
//        rawrtc_ice_gatherer_error_handler* const ice_candidate_error_handler, // nullable
//        rawrtc_peer_connection_signaling_state_change_handler* const signaling_state_change_handler, // nullable
//        rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler, // nullable
//        rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler, // nullable
        rawrtc_peer_connection_state_change_handler* const connection_state_change_handler //nullable
//        rawrtc_peer_connection_fingerprint_failure_handler* const fingerprint_failure_handler // nullable
) {
    struct rawrtc_peer_connection* connection;
    enum rawrtc_code error;
    struct sa address;

    // Check arguments
    if (!connectionp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    connection = mem_zalloc(sizeof(*connection), rawrtc_peer_connection_destroy);
    if (!connection) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Create ICE gather options
    // TODO: Get from arguments
    error = rawrtc_ice_gather_options_create(
            &connection->gather_options, RAWRTC_ICE_GATHER_POLICY_ALL);
    if (error) {
        goto out;
    }

    // Create SDP session (use IPv4 unspecified as session address)
    sa_set_in(&address, INADDR_ANY, 0);
    error = rawrtc_error_to_code(sdp_session_alloc(&connection->sdp_session, &address));
    if (error) {
        goto out;
    }

    // Set fields/reference
    connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_NEW;
    connection->connection_state_change_handler = connection_state_change_handler;
    connection->data_transport_type = RAWRTC_DATA_TRANSPORT_TYPE_SCTP;

out:
    if (error) {
        mem_deref(connection);
    } else {
        // Set pointer & done
        *connectionp = connection;
    }
    return error;
}

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
static enum rawrtc_code add_sctp_data_channel(
        struct sdp_session* const session, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
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
        struct sdp_session* const session, // not checked
        char const* const mids // not checked
) {
    int err;

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
 * Create an offer.
 */
enum rawrtc_code rawrtc_peer_connection_create_offer(
        struct mbuf** const descriptionp,
        struct rawrtc_peer_connection* const connection,
        bool const sctp_sdp_06
) {
    char const* const mid = "rawrtc-sctp-dc";
    bool bundle_only = false;
    enum rawrtc_code error;

    // TODO
    struct sdp_session* session = connection->sdp_session;

    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if already created
    // TODO: Do ICE restart (?)
//    if (connection->local_description) {
//        return RAWRTC_CODE_NOT_IMPLEMENTED;
//    }
    if (connection->context.ice_gatherer &&
            connection->context.ice_gatherer->state != RAWRTC_ICE_GATHERER_STATE_NEW) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Session attributes
    error = set_session_attributes(session, mid);
    if (error) {
        goto out;
    }
    
    // Add data transport (if any)
    if (connection->context.dtls_transport && connection->context.data_transport) {
        switch (connection->context.data_transport->type) {
            case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
                // Add SCTP transport
                error = add_sctp_data_channel(
                        session, &connection->context, mid, true, bundle_only, sctp_sdp_06);
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
    error = rawrtc_error_to_code(sdp_encode(descriptionp, session, true));
    if (error) {
        goto out;
    }

    // Debug
    (void) bundle_only;
    DEBUG_PRINTF("Local description:\n%b", mbuf_buf(*descriptionp), mbuf_get_left(*descriptionp));
    DEBUG_PRINTF("%H\n", sdp_session_debug, connection->sdp_session);

out:
    return error;
}

/*
 * Create an answer.
 */
enum rawrtc_code rawrtc_peer_connection_create_answer(
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if already created
    // TODO: Do ICE restart (?)
//    if (connection->local_description) {
//        return RAWRTC_CODE_NOT_IMPLEMENTED;
//    }
    if (connection->context.ice_gatherer &&
        connection->context.ice_gatherer->state != RAWRTC_ICE_GATHERER_STATE_NEW) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    return RAWRTC_CODE_NOT_IMPLEMENTED;
}

/*
 * When the ICE configuration changes in a way that requires a new
   gathering phase, a 'needs-ice-restart' bit is set.  When this bit is
   set, calls to the createOffer API will generate new ICE credentials.
   This bit is cleared by a call to the setLocalDescription API with new
   ICE credentials
 */

/*
 * Set local description.
 * TODO: Start gathering for each new or recycled (?) m-line (?)
 * TODO: Start gathering if ICE credentials updated
 */
enum rawrtc_code rawrtc_peer_connection_set_local_description(

) {
    return RAWRTC_CODE_NOT_IMPLEMENTED;
}

/*
 * Set the remote description.
 */
enum rawrtc_code rawrtc_peer_connection_set_remote_description(
        struct rawrtc_peer_connection* const connection,
        struct mbuf* const description
) {
    enum rawrtc_code error;

    // Check arguments
    if (!connection || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Decode SDP
    error = rawrtc_error_to_code(sdp_decode(connection->sdp_session, description, true));
    if (error) {
        goto out;
    }

    // Debug
    DEBUG_PRINTF("Remote description:\n%b", mbuf_buf(description), mbuf_get_left(description));
    DEBUG_PRINTF("%H\n", sdp_session_debug, connection->sdp_session);

out:
    return RAWRTC_CODE_NOT_IMPLEMENTED;
}

/*
 * Parse answer.
 * TODO: amount of m-lines must be identical to offer
 * TOOD: Figure 2: JSEP State Machine
 */
// Answer:
// Don't bundle if not bundled

// Decode:
// is bundled? if yes get stuff from first (?) m-line
//   if not get all stuff from each m-line

// Get SCTP port 'No default value is defined for the SDP sctp-port attribute. Therefore, if
// the attribute is not present, the associated m- line MUST be considered invalid.' LOL.
//    sdp_session_rattr(session, "sctp-port");

/*
 * Create a data channel on a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create_data_channel(
        struct rawrtc_data_channel** const channelp, // de-referenced
        struct rawrtc_peer_connection* const connection,
        struct rawrtc_data_channel_parameters* const parameters, // referenced
        struct rawrtc_data_channel_options* const options, // nullable, referenced
        rawrtc_data_channel_open_handler* const open_handler, // nullable
        rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
        rawrtc_data_channel_error_handler* const error_handler, // nullable
        rawrtc_data_channel_close_handler* const close_handler, // nullable
        rawrtc_data_channel_message_handler* const message_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    struct rawrtc_peer_connection_context context;

    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Initialise context
    context = connection->context;

    // Get data transport
    error = get_data_transport(&context, connection);
    if (error) {
        return error;
    }

    // Create data channel
    // TODO: Fix data channel cannot be created before transports have been started
    error = rawrtc_data_channel_create(
            channelp, context.data_transport, parameters, options, open_handler,
            buffered_amount_low_handler, error_handler, close_handler, message_handler, arg);
    if (error) {
        goto out;
    }

out:
    if (error) {
        // Remove all newly created instances
        revert_context(&context, &connection->context);
    } else {
        // Apply context
        apply_context(connection, &context);
    }
    return error;
}
