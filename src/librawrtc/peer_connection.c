#include <string.h> // memcpy
#include <rawrtc.h>
#include "certificate.h"
#include "dtls_transport.h"
#include "peer_connection.h"

#define DEBUG_MODULE "peer-connection"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

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
    // TODO
    (void) arg;
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
    mem_deref(connection->gather_options);
    mem_deref(connection->sdp_session);
}

/*
 * Create a new peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create(
        struct rawrtc_peer_connection** const connectionp // de-referenced
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

    // Use IPv6 unspecified as SDP session address
    error = rawrtc_error_to_code(sa_set_str(&address, "::", 0));
    if (error) {
        goto out;
    }

    // Create SDP session
    error = rawrtc_error_to_code(sdp_session_alloc(&connection->sdp_session, &address));
    if (error) {
        goto out;
    }

    // Create ICE gather options
    // TODO: Get from arguments
    error = rawrtc_ice_gather_options_create(
            &connection->gather_options, RAWRTC_ICE_GATHER_POLICY_ALL);
    if (error) {
        goto out;
    }

    // Set fields/reference
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
 * Add SCTP transport media line to SDP session.
 */
static enum rawrtc_code add_sctp_transport(
        struct sdp_session* session, // not checked
        struct rawrtc_sctp_transport* transport // not checked
) {
    enum rawrtc_code error;
    uint16_t port;
    char* fmt;
    struct sdp_media* media = NULL;

    // Get SCTP port
    error = rawrtc_sctp_transport_get_port(&port, transport);
    if (error) {
        goto out;
    }

    // Prepare media line
    error = rawrtc_sdprintf(&fmt, "DTLS/SCTP %"PRIu16, transport->port);
    if (error) {
        goto out;
    }
    
    // Media section
    // Note: Well, browsers are stuck in 2014 and thus we cannot use the current format...
    // TODO: Use 'UDP|TCP/DTLS/SCTP' instead of 'DTLS/SCTP'
    // TODO: Use 'webrtc-datachannel' as format instead of the SCTP port
    error = rawrtc_error_to_code(sdp_media_add(&media, session, "application", 9, fmt));
    mem_deref(fmt);
    if (error) {
        goto out;
    }

    // Set dummy address
//    error = rawrtc_error_to_code(sdp_media))

    // Set SCTP port

out:
    // Un-reference & done
    mem_deref(media);
    return error;
}

/*
 * Set session attributes on SDP.
 */
static enum rawrtc_code set_session_attributes(
        struct sdp_session* session // not checked
) {
    int err;

    // Trickle ICE
    err = sdp_session_set_lattr(session, true, "ice-options", "trickle");
    
    // WebRTC Identity
    // (N/A)

    // Bundle media (we currently only support a single SCTP transport)
    err |= sdp_session_set_lattr(session, true, "group", "BUNDLE", "data-1");
    
    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Create an offer.
 */
enum rawrtc_code rawrtc_peer_connection_create_offer(
        struct rawrtc_peer_connection* const connection
) {
    enum rawrtc_code error;
    struct mbuf* description = NULL;

    // TODO
    struct sdp_session* session = connection->sdp_session;

    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if already created
    // TODO: Do ICE restart (?)
    if (connection->local_description) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Session attributes
    error = set_session_attributes(session);
    if (error) {
        goto out;
    }
    
    // Add data transport (if any)
    if (connection->context.data_transport) {
        switch (connection->context.data_transport->type) {
            case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
                error = add_sctp_transport(
                        session, connection->context.data_transport->transport);
                break;
            default:
                error = RAWRTC_CODE_UNKNOWN_ERROR;
                break;
        }
        if (error) {
            goto out;
        }
    }

    // Encode SDP
    error = rawrtc_error_to_code(sdp_encode(&description, session, true));
    if (error) {
        goto out;
    }

    // Debug
    DEBUG_PRINTF("Local description:\n%b", mbuf_buf(description), mbuf_get_left(description));
    DEBUG_PRINTF("SDP session: %H\n", sdp_session_debug, connection->sdp_session);

out:
    mem_deref(description);
    return error;
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
        connection->context = context;
    }
    return error;
}
