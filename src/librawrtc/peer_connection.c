#include <rawrtc.h>
#include "ice_server.h"
#include "ice_gather_options.h"
#include "certificate.h"
#include "dtls_transport.h"
#include "peer_connection_description.h"
#include "peer_connection_ice_candidate.h"
#include "peer_connection.h"

#define DEBUG_MODULE "peer-connection"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

// Constants
uint16_t const discard_port = 9;

/*
 * Change the signalling state.
 * Will call the corresponding handler.
 */
static void set_signaling_state(
        struct rawrtc_peer_connection* const connection, // not checked
        enum rawrtc_signaling_state const state
) {
    // Set state
    connection->signaling_state = state;

    // Call handler (if any)
    if (connection->signaling_state_change_handler) {
        connection->signaling_state_change_handler(state, connection->arg);
    }
}

/*
 * Close the peer connection. This will stop all transports and update
 * all affected states appropriately.
 */
static void peer_connection_close(
        struct rawrtc_peer_connection* const connection // not checked
) {
    (void) connection;

    // TODO: Stop all transports
    DEBUG_WARNING("TODO: Stop all transports\n");

    // TODO: Update states (?)
    DEBUG_WARNING("TODO: Update states (?)\n");

    // Update signalling state
    set_signaling_state(connection, RAWRTC_SIGNALING_STATE_CLOSED);
}


/*
 * All the nasty SDP stuff has been done. Fire it all up - YAY!
 */
static enum rawrtc_code peer_connection_start(
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_peer_connection_context* const context = &connection->context;
    struct rawrtc_peer_connection_description* description;
    enum rawrtc_ice_role ice_role;
    struct le* le;

    // Check if it's too early to start
    if (!connection->local_description || !connection->remote_description) {
        return RAWRTC_CODE_NO_VALUE;
    }

    DEBUG_INFO("Local and remote description set, starting transports\n");
    description = connection->remote_description;

    // Determine ICE role
    // TODO: Is this correct?
    switch (description->type) {
        case RAWRTC_SDP_TYPE_OFFER:
            ice_role = RAWRTC_ICE_ROLE_CONTROLLED;
            break;
        case RAWRTC_SDP_TYPE_ANSWER:
            ice_role = RAWRTC_ICE_ROLE_CONTROLLING;
            break;
        default:
            DEBUG_WARNING("Cannot determine ICE role from SDP type %s, report this!\n",
                          rawrtc_sdp_type_to_str(description->type));
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }

    // Start ICE transport
    error = rawrtc_ice_transport_start(
            context->ice_transport, context->ice_gatherer, description->ice_parameters, ice_role);
    if (error) {
        return error;
    }

    // Start data transport
    switch (context->data_transport->type) {
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP: {
            struct rawrtc_sctp_transport* const sctp_transport = context->data_transport->transport;

            // Start DTLS transport
            error = rawrtc_dtls_transport_start(context->dtls_transport, description->dtls_parameters);
            if (error) {
                return error;
            }

            // Start SCTP transport
            error = rawrtc_sctp_transport_start(
                    sctp_transport, description->sctp_capabilities, description->sctp_port);
            if (error) {
                return error;
            }
            break;
        }
        default:
            DEBUG_WARNING("Invalid data transport type\n");
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }

    // Add remote ICE candidates
    for (le = list_head(&description->ice_candidates); le != NULL; le = le->next) {
        struct rawrtc_peer_connection_ice_candidate* const candidate = le->data;
        error = rawrtc_peer_connection_add_ice_candidate(connection, candidate);
        if (error) {
            DEBUG_WARNING("Unable to add remote candidate, reason: %s\n",
                          rawrtc_code_to_str(error));
            // Note: Continuing here since other candidates may work
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
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

/*
 * Add candidate to description and announce candidate.
 */
void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const ortc_candidate,
        char const * const url,
        void* const arg
) {
    struct rawrtc_peer_connection* const connection = arg;
    enum rawrtc_code error;
    char* username_fragment = NULL;
    struct rawrtc_peer_connection_ice_candidate* candidate = NULL;

    if (ortc_candidate) {
        // Copy username fragment (is going to be referenced later)
        error = rawrtc_strdup(
                &username_fragment, connection->context.ice_gatherer->ice_username_fragment);
        if (error) {
            DEBUG_WARNING("Unable to copy username fragment from ICE gatherer, reason: %s\n",
                          rawrtc_code_to_str(error));
            return;
        }

        // Create candidate
        // Note: The local description will exist at this point since we start gathering when the
        //       local description is being set.
        error = rawrtc_peer_connection_ice_candidate_from_ortc_candidate(
                &candidate, ortc_candidate, connection->local_description->mid,
                &connection->local_description->media_line_index, username_fragment);
        if (error) {
            DEBUG_WARNING("Unable to create local candidate from ORTC candidate, reason: %s\n",
                          rawrtc_code_to_str(error));
            goto out;
        }
    }

    // Add candidate (or end-of-candidate) to description
    error = rawrtc_peer_connection_description_add_candidate(
            connection->local_description, candidate);
    if (error) {
        DEBUG_WARNING("Unable to add local candidate to local description, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Call handler
    if (connection->local_candidate_handler) {
        connection->local_candidate_handler(candidate, url, connection->arg);
    }
    
out:
    // Un-reference
    mem_deref(username_fragment);
}

void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate,
        char const * const url,
        uint16_t const error_code,
        char const * const error_text,
        void* const arg
) {
    (void) host_candidate; (void) error_code; (void) arg;
    // TODO: HANDLE ICE gatherer error
    DEBUG_WARNING("TODO: HANDLE ICE gatherer error, URL: %s, reason: %s\n", url, error_text);
}

void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state,
        void* const arg
) {
    (void) arg;
    // TODO: HANDLE ICE gatherer state
    DEBUG_WARNING("HANDLE ICE gatherer state: %s\n", rawrtc_ice_gatherer_state_to_name(state));
}

/*
 * Lazy-create an ICE gatherer.
 */
static enum rawrtc_code get_ice_gatherer(
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_ice_gather_options* options;
    struct rawrtc_ice_gatherer* gatherer = NULL;
    struct le* le;

    // Already created?
    if (context->ice_gatherer) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Create ICE gather options
    error = rawrtc_ice_gather_options_create(
            &options, connection->configuration->gather_policy);
    if (error) {
        return error;
    }

    // Add ICE servers to gather options
    for (le = list_head(&connection->configuration->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const source_server = le->data;
        struct rawrtc_ice_server* server;

        // Copy ICE server
        error = rawrtc_ice_server_copy(&server, source_server);
        if (error) {
            goto out;
        }

        // Add ICE server to gather options
        error = rawrtc_ice_gather_options_add_server_internal(options, server);
        if (error) {
            mem_deref(server);
            goto out;
        }
    }

    // Create ICE gatherer
    error = rawrtc_ice_gatherer_create(
            &gatherer, options, ice_gatherer_state_change_handler,
            ice_gatherer_error_handler, ice_gatherer_local_candidate_handler, connection);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(gatherer);
        mem_deref(options);
    } else {
        // Set pointers & done
        context->gather_options = options;
        context->ice_gatherer = gatherer;
    }

    return error;
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
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP: {
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
            break;
        }
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
    peer_connection_close(connection);

    // Un-reference
    mem_deref(connection->context.data_transport);
    mem_deref(connection->context.dtls_transport);
    list_flush(&connection->context.certificates);
    mem_deref(connection->context.ice_transport);
    mem_deref(connection->context.ice_gatherer);
    mem_deref(connection->context.gather_options);
    mem_deref(connection->remote_description);
    mem_deref(connection->local_description);
    mem_deref(connection->configuration);
}

/*
 * Create a new peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_create(
        struct rawrtc_peer_connection** const connectionp, // de-referenced
        struct rawrtc_peer_connection_configuration* configuration, // referenced
        rawrtc_negotiation_needed_handler* const negotiation_needed_handler, // nullable
        rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler, // nullable
//        rawrtc_ice_gatherer_error_handler* const ice_candidate_error_handler, // nullable
        rawrtc_signaling_state_change_handler* const signaling_state_change_handler, // nullable
//        rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler, // nullable
//        rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler, // nullable
        rawrtc_peer_connection_state_change_handler* const connection_state_change_handler, //nullable
//        rawrtc_peer_connection_fingerprint_failure_handler* const fingerprint_failure_handler // nullable
        void* const arg // nullable
) {
    struct rawrtc_peer_connection* connection;

    // Check arguments
    if (!connectionp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    connection = mem_zalloc(sizeof(*connection), rawrtc_peer_connection_destroy);
    if (!connection) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    connection->signaling_state = RAWRTC_SIGNALING_STATE_STABLE;
    connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_NEW;
    connection->configuration = mem_ref(configuration);
    connection->negotiation_needed_handler = negotiation_needed_handler;
    connection->local_candidate_handler = local_candidate_handler;
    connection->signaling_state_change_handler = signaling_state_change_handler;
    connection->connection_state_change_handler = connection_state_change_handler;
    connection->data_transport_type = RAWRTC_DATA_TRANSPORT_TYPE_SCTP;
    connection->arg = arg;

    // Set pointer & done
    *connectionp = connection;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create an offer.
 */
enum rawrtc_code rawrtc_peer_connection_create_offer(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection,
        bool const ice_restart
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Support ICE restart
    if (ice_restart) {
        DEBUG_WARNING("ICE restart currently not supported\n");
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // TODO: Allow subsequent offers
    if (connection->local_description) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Create description
    return rawrtc_peer_connection_description_create_internal(descriptionp, connection, true);
}

/*
 * Create an answer.
 */
enum rawrtc_code rawrtc_peer_connection_create_answer(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // TODO: Allow subsequent answers
    if (connection->local_description) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Create description
    return rawrtc_peer_connection_description_create_internal(descriptionp, connection, false);
}

/*
 * Set and apply the local description.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_description(
        struct rawrtc_peer_connection* const connection,
        struct rawrtc_peer_connection_description* const description // referenced
) {
    bool initial_description = true;
    enum rawrtc_code error;

    // Check arguments
    if (!connection || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure it has been created by the local peer connection.
    if (description->connection != connection) {
        // Yeah, sorry, nope, I'm not parsing all this SDP nonsense again just to check
        // what kind of nasty things could have been done in the meantime.
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Allow changing the local description
    if (connection->local_description) {
        initial_description = false;
        (void) initial_description;
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // We only accept 'offer' or 'answer' at the moment
    // TODO: Handle the other ones as well
    if (description->type != RAWRTC_SDP_TYPE_OFFER && description->type != RAWRTC_SDP_TYPE_ANSWER) {
        DEBUG_WARNING("Only 'offer' or 'answer' descriptions can be handled at the moment\n");
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check SDP type
    DEBUG_PRINTF(
            "Set local description: %s (local), %s (remote)\n",
            rawrtc_sdp_type_to_str(description->type),
            connection->remote_description ? rawrtc_sdp_type_to_str(
                    connection->remote_description->type) : "n/a");
    if (connection->remote_description) {
        switch (description->type) {
            case RAWRTC_SDP_TYPE_OFFER:
                // We have a remote description and get an offer. This requires renegotiation we
                // currently don't support.
                // TODO: Add support for this
                DEBUG_WARNING("There's no support for renegotiation at the moment.\n");
                return RAWRTC_CODE_NOT_IMPLEMENTED;
            case RAWRTC_SDP_TYPE_ANSWER:
                // We have a remote description and get an answer. Sanity-check that the remote
                // description is an offer.
                if (connection->remote_description->type != RAWRTC_SDP_TYPE_OFFER) {
                    DEBUG_WARNING(
                            "Got 'answer' but remote description is '%s'\n",
                            rawrtc_sdp_type_to_str(connection->remote_description->type));
                    return RAWRTC_CODE_INVALID_STATE;
                }
                break;
            default:
                DEBUG_WARNING("Unknown SDP type, please report this!\n");
                return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    } else {
        switch (description->type) {
            case RAWRTC_SDP_TYPE_OFFER:
                // We have no remote description and get an offer. Fine.
                break;
            case RAWRTC_SDP_TYPE_ANSWER:
                // We have no remote description and get an answer. Not going to work.
                DEBUG_WARNING("Got 'answer' but have no remote description\n");
                return RAWRTC_CODE_INVALID_STATE;
            default:
                DEBUG_WARNING("Unknown SDP type, please report this!\n");
                return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    }

    // Remove reference to self
    description->connection = mem_deref(description->connection);

    // Set local description
    connection->local_description = mem_ref(description);

    // Start gathering (if initial description)
    if (initial_description) {
        error = rawrtc_ice_gatherer_gather(connection->context.ice_gatherer, NULL);
        if (error) {
            DEBUG_WARNING("Unable to start gathering, reason: %s\n", rawrtc_code_to_str(error));
            return error;
        }
    }

    // Start peer connection if both description are set
    error = peer_connection_start(connection);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        DEBUG_WARNING("Unable to start peer connection, reason: %s\n", rawrtc_code_to_str(error));
        return error;
    }

    // Update signalling state
    switch (connection->signaling_state) {
        case RAWRTC_SIGNALING_STATE_STABLE:
            // Can only be an offer or it would not have been accepted
            set_signaling_state(connection, RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER);
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER:
            // Update of the local offer, nothing to do
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER:
            // Can only be an answer or it would not have been accepted
            // Note: This may change once we accept PR answers
            set_signaling_state(connection, RAWRTC_SIGNALING_STATE_STABLE);
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_PROVISIONAL_ANSWER:
            // Impossible state
            // Note: This may change once we accept PR answers
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_PROVISIONAL_ANSWER:
            // Impossible state
            // Note: This may change once we accept PR answers
            break;
        case RAWRTC_SIGNALING_STATE_CLOSED:
            // Impossible state
            break;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set and apply the remote description.
 */
enum rawrtc_code rawrtc_peer_connection_set_remote_description(
        struct rawrtc_peer_connection* const connection,
        struct rawrtc_peer_connection_description* const description // referenced
) {
    enum rawrtc_code error;
    struct rawrtc_peer_connection_context context;

    // Check arguments
    if (!connection || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Allow changing the remote description
    if (connection->remote_description) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // We only accept 'offer' or 'answer' at the moment
    // TODO: Handle the other ones as well
    if (description->type != RAWRTC_SDP_TYPE_OFFER && description->type != RAWRTC_SDP_TYPE_ANSWER) {
        DEBUG_WARNING("Only 'offer' or 'answer' descriptions can be handled at the moment\n");
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check SDP type
    DEBUG_PRINTF(
            "Set remote description: %s (local), %s (remote)\n",
            connection->local_description ? rawrtc_sdp_type_to_str(
                    connection->local_description->type) : "n/a",
            rawrtc_sdp_type_to_str(description->type));
    if (connection->local_description) {
        switch (description->type) {
            case RAWRTC_SDP_TYPE_OFFER:
                // We have a local description and get an offer. This requires renegotiation we
                // currently don't support.
                // TODO: Add support for this
                DEBUG_WARNING("There's no support for renegotiation at the moment.\n");
                return RAWRTC_CODE_NOT_IMPLEMENTED;
            case RAWRTC_SDP_TYPE_ANSWER:
                // We have a local description and get an answer. Sanity-check that the local
                // description is an offer.
                if (connection->local_description->type != RAWRTC_SDP_TYPE_OFFER) {
                    DEBUG_WARNING(
                            "Got 'answer' but local description is '%s'\n",
                            rawrtc_sdp_type_to_str(connection->local_description->type));
                    return RAWRTC_CODE_INVALID_STATE;
                }
                break;
            default:
                DEBUG_WARNING("Unknown SDP type, please report this!\n");
                return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    } else {
        switch (description->type) {
            case RAWRTC_SDP_TYPE_OFFER:
                // We have no local description and get an offer. Fine.
                break;
            case RAWRTC_SDP_TYPE_ANSWER:
                // We have no local description and get an answer. Not going to work.
                DEBUG_WARNING("Got 'answer' but have no local description\n");
                return RAWRTC_CODE_INVALID_STATE;
            default:
                DEBUG_WARNING("Unknown SDP type, please report this!\n");
                return RAWRTC_CODE_UNKNOWN_ERROR;
        }
    }

    // No trickle ICE? Ensure we have all candidates
    if (!description->trickle_ice && !description->end_of_candidates) {
        DEBUG_NOTICE("No trickle ICE indicated but don't have all candidates\n");
        // Note: We continue since we still accept further candidates.
    }

    // No remote media 'application' line?
    if (!description->remote_media_line) {
        DEBUG_WARNING("No remote media 'application' line for data channels found\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // No ICE parameters?
    // Note: We either have valid ICE parameters or none at this point
    if (!description->ice_parameters) {
        DEBUG_WARNING("Required ICE parameters not present\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // No DTLS parameters?
    // Note: We either have valid DTLS parameters or none at this point
    if (!description->dtls_parameters) {
        DEBUG_WARNING("Required DTLS parameters not present\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // No SCTP capabilities or port?
    // Note: We either have valid SCTP capabilities or none at this point
    if (!description->sctp_capabilities) {
        DEBUG_WARNING("Required SCTP capabilities not present\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
    if (description->sctp_port == 0) {
        DEBUG_WARNING("Invalid SCTP port (0)\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set remote description
    connection->remote_description = mem_ref(description);

    // Initialise context
    context = connection->context;

    // Create a data transport if we're answering
    if (description->type == RAWRTC_SDP_TYPE_OFFER) {
        // Get data transport
        error = get_data_transport(&context, connection);
        if (error) {
            DEBUG_WARNING("Unable to create data transport, reason: %s\n",
                          rawrtc_code_to_str(error));
            return error;
        }

        // Apply context
        apply_context(connection, &context);
    }

    // Start peer connection if both description are set
    error = peer_connection_start(connection);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        DEBUG_WARNING("Unable to start peer connection, reason: %s\n", rawrtc_code_to_str(error));
        return error;
    }

    // Update signalling state
    switch (connection->signaling_state) {
        case RAWRTC_SIGNALING_STATE_STABLE:
            // Can only be an offer or it would not have been accepted
            set_signaling_state(connection, RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER);
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_OFFER:
            // Can only be an answer or it would not have been accepted
            // Note: This may change once we accept PR answers
            set_signaling_state(connection, RAWRTC_SIGNALING_STATE_STABLE);
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_OFFER:
            // Update of the remote offer, nothing to do
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_LOCAL_PROVISIONAL_ANSWER:
            // Impossible state
            // Note: This may change once we accept PR answers
            break;
        case RAWRTC_SIGNALING_STATE_HAVE_REMOTE_PROVISIONAL_ANSWER:
            // Impossible state
            // Note: This may change once we accept PR answers
            break;
        case RAWRTC_SIGNALING_STATE_CLOSED:
            // Impossible state
            break;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE candidate to the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_add_ice_candidate(
        struct rawrtc_peer_connection* const connection,
        struct rawrtc_peer_connection_ice_candidate* const candidate
) {
    enum rawrtc_code error;
    struct rawrtc_peer_connection_description* description;

    // Check arguments
    if (!connection || !candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure there's a remote description
    description = connection->remote_description;
    if (!description) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Note: We can be sure that either 'mid' or the media line index is present at this point.

    // Check if the 'mid' matches (if any)
    // TODO: Once we support further media lines, we need to look up the appropriate transport here
    if (candidate->mid && description->mid && str_cmp(candidate->mid, description->mid) != 0) {
        DEBUG_WARNING("No matching 'mid' in remote description\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if the media line index matches (if any)
    if (candidate->media_line_index >= 0 && candidate->media_line_index <= UINT8_MAX
        && ((uint8_t) candidate->media_line_index) != description->media_line_index) {
        DEBUG_WARNING("No matching media line index in remote description\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if the username fragment matches (if any)
    // TODO: This would need to be done across ICE generations
    if (candidate->username_fragment) {
        char* username_fragment;
        bool matching;

        // Get username fragment from the remote ICE parameters
        error = rawrtc_ice_parameters_get_username_fragment(
                &username_fragment, description->ice_parameters);
        if (error) {
            DEBUG_WARNING("Unable to retrieve username fragment, reason: %s\n",
                          rawrtc_code_to_str(error));
            return error;
        }

        // Compare username fragments
        matching = str_cmp(candidate->username_fragment, username_fragment) == 0;
        mem_deref(username_fragment);
        if (!matching) {
            DEBUG_WARNING("Username fragments don't match\n");
            return RAWRTC_CODE_INVALID_ARGUMENT;
        }
    }

    // Add ICE candidate
    return rawrtc_ice_transport_add_remote_candidate(
            connection->context.ice_transport, candidate->candidate);
}

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

    // Check state
    // TODO: Support new offer/answer
    if (connection->connection_state != RAWRTC_PEER_CONNECTION_STATE_NEW) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Initialise context
    context = connection->context;

    // Get data transport
    error = get_data_transport(&context, connection);
    if (error) {
        DEBUG_WARNING("Unable to create data transport, reason: %s\n",
                      rawrtc_code_to_str(error));
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

        // Negotiation needed?
        if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_NEW
            && connection->negotiation_needed_handler) {
            connection->negotiation_needed_handler(connection->arg);
        }
    }
    return error;
}

/*
 * Get local description.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_description(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Reference description (if any)
    if (connection->local_description) {
        *descriptionp = mem_ref(connection->local_description);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get remote description.
 */
enum rawrtc_code rawrtc_peer_connection_get_remote_description(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Reference description (if any)
    if (connection->remote_description) {
        *descriptionp = mem_ref(connection->remote_description);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}
