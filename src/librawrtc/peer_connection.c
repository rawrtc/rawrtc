#include <rawrtcc/internal/certificate.h>
#include <rawrtc.h>
#include "ice_server.h"
#include "ice_gather_options.h"
#include "ice_gatherer.h"
#include "ice_candidate.h"
#include "dtls_transport.h"
#include "peer_connection_configuration.h"
#include "peer_connection_description.h"
#include "peer_connection_ice_candidate.h"
#include "peer_connection.h"

#define DEBUG_MODULE "peer-connection"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

// Constants
uint16_t const discard_port = 9;

/*
 * Change the signalling state.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
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
 * Change the connection state to a specific state.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_connection_state(
        struct rawrtc_peer_connection* const connection, // not checked
        enum rawrtc_peer_connection_state const state
) {
    // Set state
    connection->connection_state = state;

    // Call handler (if any)
    if (connection->connection_state_change_handler) {
        connection->connection_state_change_handler(state, connection->arg);
    }
}

/*
 * Update connection state.
 * Will call the corresponding handler.
 */
static void update_connection_state(
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;
    enum rawrtc_ice_transport_state ice_transport_state = RAWRTC_ICE_TRANSPORT_STATE_NEW;
    enum rawrtc_dtls_transport_state dtls_transport_state = RAWRTC_DTLS_TRANSPORT_STATE_NEW;
    enum rawrtc_peer_connection_state connection_state;

    // Nothing beats the closed state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return;
    }

    // Get ICE transport and DTLS transport states
    if (connection->context.ice_transport) {
        error = rawrtc_ice_transport_get_state(
                &ice_transport_state, connection->context.ice_transport);
        if (error) {
            DEBUG_WARNING("Unable to get ICE transport state, reason: %s\n",
                          rawrtc_error_to_code(error));
        }
    }
    if (connection->context.dtls_transport) {
        error = rawrtc_dtls_transport_get_state(
                &dtls_transport_state, connection->context.dtls_transport);
        if (error) {
            DEBUG_WARNING("Unable to get DTLS transport state, reason: %s\n",
                          rawrtc_error_to_code(error));
        }
    }

    // Note: This follows the mindbogglingly confusing W3C spec description - it's just not
    //       super-obvious. We start with states that are easy to detect and remove more and more
    //       states from the equation.

    // Failed: Any in the 'failed' state
    if (ice_transport_state == RAWRTC_ICE_TRANSPORT_STATE_FAILED
        || dtls_transport_state == RAWRTC_DTLS_TRANSPORT_STATE_FAILED) {
        connection_state = RAWRTC_PEER_CONNECTION_STATE_FAILED;
        goto out;
    }

    // Connecting: Any in the 'connecting' or 'checking' state
    if (ice_transport_state == RAWRTC_ICE_TRANSPORT_STATE_CHECKING
        || dtls_transport_state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING) {
        connection_state = RAWRTC_PEER_CONNECTION_STATE_CONNECTING;
        goto out;
    }

    // Disconnected: Any in the 'disconnected' state
    if (ice_transport_state == RAWRTC_ICE_TRANSPORT_STATE_DISCONNECTED) {
        connection_state = RAWRTC_PEER_CONNECTION_STATE_DISCONNECTED;
        goto out;
    }

    // New: Any in 'new' or all in 'closed'
    if (ice_transport_state == RAWRTC_ICE_TRANSPORT_STATE_NEW
        || dtls_transport_state == RAWRTC_DTLS_TRANSPORT_STATE_NEW
        || (ice_transport_state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED
            && dtls_transport_state == RAWRTC_DTLS_TRANSPORT_STATE_CLOSED)) {
        connection_state = RAWRTC_PEER_CONNECTION_STATE_NEW;
        goto out;
    }

    // Connected
    connection_state = RAWRTC_PEER_CONNECTION_STATE_CONNECTED;

out:
    // Debug
    DEBUG_PRINTF(
            "ICE (%s) + DTLS (%s) = PC %s\n",
            rawrtc_ice_transport_state_to_name(ice_transport_state),
            rawrtc_dtls_transport_state_to_name(dtls_transport_state),
            rawrtc_peer_connection_state_to_name(connection_state));

    // Check if the state would change
    if (connection->connection_state == connection_state) {
        return;
    }

    // Set state
    connection->connection_state = connection_state;

    // Call handler (if any)
    if (connection->connection_state_change_handler) {
        connection->connection_state_change_handler(connection_state, connection->arg);
    }
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
    enum rawrtc_data_transport_type data_transport_type;
    void* data_transport;
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

    // Get data transport
    error = rawrtc_data_transport_get_transport(
            &data_transport_type, &data_transport, context->data_transport);
    if (error) {
        return error;
    }

    // Start data transport
    switch (data_transport_type) {
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP: {
            struct rawrtc_sctp_transport* const sctp_transport = data_transport;

            // Start DTLS transport
            error = rawrtc_dtls_transport_start(
                    context->dtls_transport, description->dtls_parameters);
            if (error) {
                goto out;
            }

            // Start SCTP transport
            error = rawrtc_sctp_transport_start(
                    sctp_transport, description->sctp_capabilities, description->sctp_port);
            if (error) {
                goto out;
            }
            break;
        }
        default:
            DEBUG_WARNING("Invalid data transport type: %s\n",
                          rawrtc_data_transport_type_to_str(data_transport_type));
            error = RAWRTC_CODE_UNSUPPORTED_PROTOCOL;
            goto out;
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
    error = RAWRTC_CODE_SUCCESS;

out:
    mem_deref(data_transport);
    return error;
}

/*
 * Remove all instances that have been created which are not
 * associated to the peer connection.
 */
static void revert_context(
        struct rawrtc_peer_connection_context* const new, // not checked
        struct rawrtc_peer_connection_context* const current // not checked
) {
    if (new->data_transport != current->data_transport) {
        mem_deref(new->data_transport);
    }
    if (new->dtls_transport != current->dtls_transport) {
        mem_deref(new->dtls_transport);
    }
    // TODO: This check is brittle...
    if (!list_isempty(&new->certificates) && list_isempty(&current->certificates)) {
        list_flush(&new->certificates);
    }
    if (new->ice_transport != current->ice_transport) {
        mem_deref(new->ice_transport);
    }
    if (new->ice_gatherer != current->ice_gatherer) {
        mem_deref(new->ice_gatherer);
    }
    if (new->gather_options != current->gather_options) {
        mem_deref(new->gather_options);
    }
}

/*
 * Apply all instances on a peer connection.
 * Return if anything inside the context has changed.
 */
static bool apply_context(
        struct rawrtc_peer_connection_context* const new, // not checked
        struct rawrtc_peer_connection_context* const current // not checked
) {
    bool changed = false;
    if (new->data_transport != current->data_transport) {
        current->data_transport = new->data_transport;
        changed = true;
    }
    if (new->dtls_transport != current->dtls_transport) {
        current->dtls_transport = new->dtls_transport;
        str_ncpy(current->dtls_id, new->dtls_id, DTLS_ID_LENGTH + 1);
        changed = true;
    }
    // TODO: This check is brittle...
    if (!list_isempty(&new->certificates) && list_isempty(&current->certificates)) {
        current->certificates = new->certificates;
        changed = true;
    }
    if (new->ice_transport != current->ice_transport) {
        current->ice_transport = new->ice_transport;
        changed = true;
    }
    if (new->ice_gatherer != current->ice_gatherer) {
        current->ice_gatherer = new->ice_gatherer;
        changed = true;
    }
    if (new->gather_options != current->gather_options) {
        current->gather_options = new->gather_options;
        changed = true;
    }
    return changed;
}

/*
 * Wrap an ORTC ICE candidate to a peer connection ICE candidate.
 */
enum rawrtc_code local_ortc_candidate_to_candidate(
        struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced, not checked
        struct rawrtc_ice_candidate* const ortc_candidate, // not checked
        struct rawrtc_peer_connection* const connection // not checked
) {
    enum rawrtc_code error;
    char* username_fragment;
    struct rawrtc_peer_connection_ice_candidate* candidate;

    // Copy username fragment (is going to be referenced later)
    error = rawrtc_strdup(
            &username_fragment, connection->context.ice_gatherer->ice_username_fragment);
    if (error) {
        DEBUG_WARNING("Unable to copy username fragment from ICE gatherer, reason: %s\n",
                      rawrtc_code_to_str(error));
        return error;
    }

    // Create candidate
    // Note: The local description will exist at this point since we start gathering when the
    //       local description is being set.
    error = rawrtc_peer_connection_ice_candidate_from_ortc_candidate(
            &candidate, ortc_candidate, connection->local_description->mid,
            &connection->local_description->media_line_index, username_fragment);
    if (error) {
        goto out;
    }

    // Set pointer & done
    *candidatep = candidate;
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference
    mem_deref(username_fragment);
    return error;
}

/*
 * Add candidate to description and announce candidate.
 */
void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const ortc_candidate, // nullable
        char const * const url, // nullable
        void* const arg
) {
    struct rawrtc_peer_connection* const connection = arg;
    enum rawrtc_code error;
    struct rawrtc_peer_connection_ice_candidate* candidate = NULL;

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_FAILED
        || connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        DEBUG_NOTICE("Ignoring candidate in the %s state\n",
                     rawrtc_peer_connection_state_to_name(connection->connection_state));
        return;
    }

    // Wrap candidate (if any ORTC candidate)
    if (ortc_candidate) {
        error = local_ortc_candidate_to_candidate(&candidate, ortc_candidate, connection);
        if (error) {
            DEBUG_WARNING("Unable to create local candidate from ORTC candidate, reason: %s\n",
                          rawrtc_code_to_str(error));
            return;
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

    // Call handler (if any)
    if (connection->local_candidate_handler) {
        connection->local_candidate_handler(candidate, url, connection->arg);
    }

out:
    // Un-reference
    mem_deref(candidate);
}

/*
 * Announce ICE gatherer error as ICE candidate error.
 */
void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const ortc_candidate, // nullable
        char const * const url,
        uint16_t const error_code,
        char const * const error_text,
        void* const arg
) {
    struct rawrtc_peer_connection* const connection = arg;
    enum rawrtc_code error;
    struct rawrtc_peer_connection_ice_candidate* candidate = NULL;

    // Wrap candidate (if any ORTC candidate)
    if (ortc_candidate) {
        error = local_ortc_candidate_to_candidate(&candidate, ortc_candidate, connection);
        if (error) {
            DEBUG_WARNING("Unable to create local candidate from ORTC candidate, reason: %s\n",
                          rawrtc_code_to_str(error));
            return;
        }
    }

    // Call handler (if any)
    if (connection->local_candidate_error_handler) {
        connection->local_candidate_error_handler(
                candidate, url, error_code, error_text, connection->arg);
    }
}

/*
 * Filter ICE gatherer state and announce it.
 */
void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state,
        void* const arg
) {
    struct rawrtc_peer_connection* const connection = arg;

    // The only difference to the ORTC gatherer states is that there's no 'closed' state.
    if (state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return;
    }

    // Call handler (if any)
    if (connection->ice_gathering_state_change_handler) {
        connection->ice_gathering_state_change_handler(state, connection->arg);
    }
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
    (void) local; (void) remote; (void) arg;

    // There's no handler that could potentially print this, so we print it here for debug purposes
    DEBUG_PRINTF("ICE transport candidate pair change\n");
}

static void ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg
) {
    struct rawrtc_peer_connection* const connection = arg;

    // Call handler (if any)
    if (connection->ice_connection_state_change_handler) {
        connection->ice_connection_state_change_handler(state, connection->arg);
    }

    // Update connection state
    update_connection_state(connection);
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
        struct rawrtc_peer_connection_context* const context, // not checked
        struct rawrtc_peer_connection_configuration* const configuration // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_certificate* certificate;

    // Already created?
    if (!list_isempty(&context->certificates)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Certificates in the configuration? Copy them.
    if (!list_isempty(&configuration->certificates)) {
        return rawrtc_certificate_list_copy(&context->certificates, &configuration->certificates);
    }

    // Generate a certificate
    error = rawrtc_certificate_generate(&certificate, NULL);
    if (error) {
        return error;
    }

    // Add certificate to the list
    list_append(&context->certificates, &certificate->le, certificate);
    return RAWRTC_CODE_SUCCESS;
}

static void dtls_transport_error_handler(
        // TODO: error.message (probably from OpenSSL)
        void* const arg
) {
    (void) arg;
    // TODO: Print error message
    DEBUG_WARNING("DTLS transport error: %s\n", "???");
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state,
        void* const arg
) {
    struct rawrtc_peer_connection* connection = arg;
    (void) state;

    // Update connection state
    update_connection_state(connection);
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
    error = get_certificates(context, connection->configuration);
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
    (void) arg; (void) state;

    // There's no handler that could potentially print this, so we print it here for debug purposes
    DEBUG_PRINTF("SCTP transport state change: %s\n", rawrtc_sctp_transport_state_to_name(state));
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
                    connection->arg);
            if (error) {
                return error;
            }

            // Get data transport
            // Note: Since the data transport has a reference to the SCTP transport, we can still
            //       retrieve the reference later.
            error = rawrtc_sctp_transport_get_data_transport(
                    &context->data_transport, sctp_transport);
            mem_deref(sctp_transport);
            if (error) {
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

    // Unset all handlers
    rawrtc_peer_connection_unset_handlers(connection);

    // Close peer connection
    rawrtc_peer_connection_close(connection);

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
 * `*connectionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_create(
        struct rawrtc_peer_connection** const connectionp, // de-referenced
        struct rawrtc_peer_connection_configuration* configuration, // referenced
        rawrtc_negotiation_needed_handler* const negotiation_needed_handler, // nullable
        rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler, // nullable
        rawrtc_peer_connection_local_candidate_error_handler* const local_candidate_error_handler, // nullable
        rawrtc_signaling_state_change_handler* const signaling_state_change_handler, // nullable
        rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler, // nullable
        rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler, // nullable
        rawrtc_peer_connection_state_change_handler* const connection_state_change_handler, //nullable
        rawrtc_data_channel_handler* const data_channel_handler, // nullable
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
    connection->connection_state = RAWRTC_PEER_CONNECTION_STATE_NEW;
    connection->signaling_state = RAWRTC_SIGNALING_STATE_STABLE;
    connection->configuration = mem_ref(configuration);
    connection->negotiation_needed_handler = negotiation_needed_handler;
    connection->local_candidate_handler = local_candidate_handler;
    connection->local_candidate_error_handler = local_candidate_error_handler;
    connection->signaling_state_change_handler = signaling_state_change_handler;
    connection->ice_connection_state_change_handler = ice_connection_state_change_handler;
    connection->ice_gathering_state_change_handler = ice_gathering_state_change_handler;
    connection->connection_state_change_handler = connection_state_change_handler;
    connection->data_channel_handler = data_channel_handler;
    connection->data_transport_type = RAWRTC_DATA_TRANSPORT_TYPE_SCTP;
    connection->arg = arg;

    // Set pointer & done
    *connectionp = connection;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Close the peer connection. This will stop all underlying transports
 * and results in a final 'closed' state.
 */
enum rawrtc_code rawrtc_peer_connection_close(
        struct rawrtc_peer_connection* const connection
) {
    enum rawrtc_code error;

    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Update signalling & connection state
    // Note: We need to do this early or the 'closed' states when tearing down the transports may
    //       lead to surprising peer connection states such as 'connected' at the very end.
    set_signaling_state(connection, RAWRTC_SIGNALING_STATE_CLOSED);
    set_connection_state(connection, RAWRTC_PEER_CONNECTION_STATE_CLOSED);

    // Stop data transport (if any)
    if (connection->context.data_transport) {
        enum rawrtc_data_transport_type data_transport_type;
        void* data_transport;

        // Get data transport
        error = rawrtc_data_transport_get_transport(
                &data_transport_type, &data_transport, connection->context.data_transport);
        if (error) {
            DEBUG_WARNING("Unable to get data transport, reason: %s\n", rawrtc_code_to_str(error));
        } else {
            // Stop transport
            switch (data_transport_type) {
                case RAWRTC_DATA_TRANSPORT_TYPE_SCTP: {
                    struct rawrtc_sctp_transport *const sctp_transport = data_transport;
                    error = rawrtc_sctp_transport_stop(sctp_transport);
                    if (error) {
                        DEBUG_WARNING("Unable to stop SCTP transport, reason: %s\n",
                                      rawrtc_code_to_str(error));
                    }
                    break;
                }
                default:
                    DEBUG_WARNING("Invalid data transport type: %s\n",
                                  rawrtc_data_transport_type_to_str(data_transport_type));
                    break;
            }

            // Un-reference
            mem_deref(data_transport);
        }
    }

    // Stop DTLS transport (if any)
    if (connection->context.dtls_transport) {
        error = rawrtc_dtls_transport_stop(connection->context.dtls_transport);
        if (error) {
            DEBUG_WARNING("Unable to stop DTLS transport, reason: %s\n", rawrtc_code_to_str(error));
        }
    }

    // Stop ICE transport (if any)
    if (connection->context.ice_transport) {
        error = rawrtc_ice_transport_stop(connection->context.ice_transport);
        if (error) {
            DEBUG_WARNING("Unable to stop ICE transport, reason: %s\n", rawrtc_code_to_str(error));
        }
    }

    // Close ICE gatherer (if any)
    if (connection->context.ice_gatherer) {
        error = rawrtc_ice_gatherer_close(connection->context.ice_gatherer);
        if (error) {
            DEBUG_WARNING("Unable to close ICE gatherer, reason: %s\n", rawrtc_code_to_str(error));
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create an offer.
 * `*descriptionp` must be unreferenced.
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
 * `*descriptionp` must be unreferenced.
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

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
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
 * Get local description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no local description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
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

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
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
        apply_context(&context, &connection->context);
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
 * Get remote description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
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

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
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
 * Get the current signalling state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state(
        enum rawrtc_signaling_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = connection->signaling_state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the current ICE gathering state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state(
        enum rawrtc_ice_gatherer_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    // Note: The W3C spec requires us to return 'new' in case no ICE gatherer exists.
    // Note: Theoretically there's no 'closed' state on the peer connection variant. We ignore
    //       that here.
    if (connection->context.ice_gatherer) {
        return rawrtc_ice_gatherer_get_state(statep, connection->context.ice_gatherer);
    } else {
        *statep = RAWRTC_ICE_GATHERER_STATE_NEW;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current ICE connection state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state(
        enum rawrtc_ice_transport_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    // Note: The W3C spec requires us to return 'new' in case no ICE transport exists.
    if (connection->context.ice_transport) {
        return rawrtc_ice_transport_get_state(statep, connection->context.ice_transport);
    } else {
        *statep = RAWRTC_ICE_TRANSPORT_STATE_NEW;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current (peer) connection state of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state(
        enum rawrtc_peer_connection_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = connection->connection_state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get indication whether the remote peer accepts trickled ICE
 * candidates.
 *
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_can_trickle_ice_candidates(
        bool* const can_trickle_ice_candidatesp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!can_trickle_ice_candidatesp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set flag (if remote description set)
    if (connection->remote_description) {
        *can_trickle_ice_candidatesp = connection->remote_description->trickle_ice;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Create a data channel on a peer connection.
 * `*channelp` must be unreferenced.
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
    struct rawrtc_data_channel* channel = NULL;

    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (connection->connection_state == RAWRTC_PEER_CONNECTION_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Initialise context
    context = connection->context;

    // Get data transport (if no description has been set, yet)
    if (!connection->local_description && !connection->remote_description) {
        error = get_data_transport(&context, connection);
        if (error) {
            DEBUG_WARNING("Unable to create data transport, reason: %s\n",
                          rawrtc_code_to_str(error));
            return error;
        }
    }

    // Create data channel
    // TODO: Fix data channel cannot be created before transports have been started
    error = rawrtc_data_channel_create(
            &channel, context.data_transport, parameters, options, open_handler,
            buffered_amount_low_handler, error_handler, close_handler, message_handler, arg);
    if (error) {
        goto out;
    }

out:
    if (error) {
        // Un-reference
        mem_deref(channel);

        // Remove all newly created instances
        revert_context(&context, &connection->context);
    } else {
        // Apply context
        bool const negotiation_needed = apply_context(&context, &connection->context);

        // Set pointer
        *channelp = channel;

        // Negotiation needed?
        if (negotiation_needed) {
            connection->negotiation_needed_handler(connection->arg);
        }
    }
    return error;
}

/*
 * Unset the handler argument and all handlers of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_unset_handlers(
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Unset handler argument
    connection->arg = NULL;

    // Unset all handlers
    connection->data_channel_handler = NULL;
    connection->connection_state_change_handler = NULL;
    connection->ice_gathering_state_change_handler = NULL;
    connection->ice_connection_state_change_handler = NULL;
    connection->signaling_state_change_handler = NULL;
    connection->local_candidate_error_handler = NULL;
    connection->local_candidate_handler = NULL;
    connection->negotiation_needed_handler = NULL;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set the peer connection's negotiation needed handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_negotiation_needed_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_negotiation_needed_handler* const negotiation_needed_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set negotiation needed handler & done
    connection->negotiation_needed_handler = negotiation_needed_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's negotiation needed handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_negotiation_needed_handler(
        rawrtc_negotiation_needed_handler** const negotiation_needed_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!negotiation_needed_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get negotiation needed handler (if any)
    if (connection->negotiation_needed_handler) {
        *negotiation_needed_handlerp = connection->negotiation_needed_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ICE local candidate handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_local_candidate_handler* const local_candidate_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set local candidate handler & done
    connection->local_candidate_handler = local_candidate_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ICE local candidate handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_handler(
        rawrtc_peer_connection_local_candidate_handler** const local_candidate_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!local_candidate_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate handler (if any)
    if (connection->local_candidate_handler) {
        *local_candidate_handlerp = connection->local_candidate_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ICE local candidate error handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_error_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_local_candidate_error_handler* const local_candidate_error_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set local candidate error handler & done
    connection->local_candidate_error_handler = local_candidate_error_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ICE local candidate error handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_error_handler(
        rawrtc_peer_connection_local_candidate_error_handler** const local_candidate_error_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!local_candidate_error_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate error handler (if any)
    if (connection->local_candidate_error_handler) {
        *local_candidate_error_handlerp = connection->local_candidate_error_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's signaling state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_signaling_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_signaling_state_change_handler* const signaling_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set signaling state change handler & done
    connection->signaling_state_change_handler = signaling_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's signaling state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state_change_handler(
        rawrtc_signaling_state_change_handler** const signaling_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!signaling_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get signaling state change handler (if any)
    if (connection->signaling_state_change_handler) {
        *signaling_state_change_handlerp = connection->signaling_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ice connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_connection_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set ice connection state change handler & done
    connection->ice_connection_state_change_handler = ice_connection_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ice connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state_change_handler(
        rawrtc_ice_transport_state_change_handler** const ice_connection_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!ice_connection_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get ice connection state change handler (if any)
    if (connection->ice_connection_state_change_handler) {
        *ice_connection_state_change_handlerp = connection->ice_connection_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ice gathering state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_gathering_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set ice gathering state change handler & done
    connection->ice_gathering_state_change_handler = ice_gathering_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ice gathering state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state_change_handler(
        rawrtc_ice_gatherer_state_change_handler** const ice_gathering_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!ice_gathering_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get ice gathering state change handler (if any)
    if (connection->ice_gathering_state_change_handler) {
        *ice_gathering_state_change_handlerp = connection->ice_gathering_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's (peer) connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_connection_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_state_change_handler* const connection_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set (peer) connection state change handler & done
    connection->connection_state_change_handler = connection_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's (peer) connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state_change_handler(
        rawrtc_peer_connection_state_change_handler** const connection_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get (peer) connection state change handler (if any)
    if (connection->connection_state_change_handler) {
        *connection_state_change_handlerp = connection->connection_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's data channel handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_data_channel_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_data_channel_handler* const data_channel_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set data channel handler & done
    connection->data_channel_handler = data_channel_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's data channel handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_data_channel_handler(
        rawrtc_data_channel_handler** const data_channel_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!data_channel_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get data channel handler (if any)
    if (connection->data_channel_handler) {
        *data_channel_handlerp = connection->data_channel_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}
