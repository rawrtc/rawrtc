#include <rawrtc.h>
#include "candidate_helper.h"
#include "utils.h"
#include "packet_trace.h"

#define DEBUG_MODULE "candidate-helper"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Destructor for an existing candidate helper.
 */
static void rawrtc_candidate_helper_destroy(
        void* arg
) {
    struct rawrtc_candidate_helper* const candidate_helper = arg;

    // Un-reference
    mem_deref(candidate_helper->udp_helper_trace_turn);
    list_flush(&candidate_helper->turn_sessions);
    mem_deref(candidate_helper->udp_helper_trace_stun);
    list_flush(&candidate_helper->stun_sessions);
    mem_deref(candidate_helper->udp_helper_trace_ice);
    list_flush(&candidate_helper->trace_packet_helper_contexts);
    mem_deref(candidate_helper->udp_helper);
    mem_deref(candidate_helper->candidate);
    mem_deref(candidate_helper->gatherer);
}

/*
 * Create a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_create(
        struct rawrtc_candidate_helper** const candidate_helperp, // de-referenced
        struct rawrtc_ice_gatherer* gatherer,
        struct ice_lcand* const re_candidate,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    struct rawrtc_candidate_helper* candidate_helper;
    enum rawrtc_code error;

    // Check arguments
    if (!candidate_helperp || !gatherer || !re_candidate || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create candidate helper
    candidate_helper = mem_zalloc(sizeof(*candidate_helper), rawrtc_candidate_helper_destroy);
    if (!candidate_helper) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    candidate_helper->gatherer = mem_ref(gatherer);
    candidate_helper->candidate = mem_ref(re_candidate);
    candidate_helper->srflx_pending_count = 0;
    candidate_helper->relay_pending_count = 0;

    // Set receive handler
    error = rawrtc_candidate_helper_set_receive_handler(candidate_helper, receive_handler, arg);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(candidate_helper);
    } else {
        // Set pointer
        *candidate_helperp = candidate_helper;
    }
    return error;
}

/*
 * Set a receive handler on a local re candidate.
 */
static enum rawrtc_code set_receive_handler(
        struct udp_helper** udp_helperp, // de-referenced, not checked
        struct trice* const ice, // not checked
        struct ice_lcand* const re_candidate, // not checked
        enum rawrtc_layer const layer,
        udp_helper_send_h* const send_handler, // not checked
        udp_helper_recv_h* const receive_handler, // not checked
        void* const arg
) {
    enum rawrtc_code error;
    struct udp_helper* udp_helper;

    // Get local re_candidate's UDP socket
    struct udp_sock* const udp_socket = trice_lcand_sock(ice, re_candidate);
    if (!udp_socket) {
        return RAWRTC_CODE_NO_SOCKET;
    }

    // Create UDP helper
    error = rawrtc_error_to_code(udp_register_helper(
            &udp_helper, udp_socket, layer, send_handler,
            receive_handler, arg));
    if (error) {
        return error;
    }

    // TODO: What about TCP helpers?

    // Unset current helper (if any) and set new helper
    mem_deref(*udp_helperp);
    *udp_helperp = udp_helper;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set a candidate helper's receive handler.
 */
enum rawrtc_code rawrtc_candidate_helper_set_receive_handler(
        struct rawrtc_candidate_helper* const candidate_helper,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    enum rawrtc_code error;

    // Check arguments
    if (!candidate_helper || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set receive handler on local host candidate
    error = set_receive_handler(
            &candidate_helper->udp_helper, candidate_helper->gatherer->ice,
            candidate_helper->candidate, RAWRTC_LAYER_DTLS_SRTP, NULL, receive_handler, arg);
    if (error) {
        DEBUG_WARNING("Unable to set local host candidate receive handler, reason: %s\n",
                      rawrtc_code_to_str(error));
        return error;
    }

    // Note: Applying the receive handler to local STUN session's candidates is not needed as they
    //       do not have a socket (they are tied to the host candidate's socket).

    // Note: Applying the receive handler to local TURN session's candidates is not needed as they
    //       do not have their own socket. This may change once we add TCP support.

    // Done
    return error;
}

/*
 * Attach a packet trace helper to a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_attach_packet_trace_handler(
        struct udp_helper** const udp_helperp, // de-referenced
        struct rawrtc_candidate_helper* const candidate_helper,
        FILE* const trace_handle,
        enum rawrtc_layer const trace_layer
) {
    struct rawrtc_packet_trace_helper_context* context = NULL;
    struct udp_helper* udp_helper = NULL;
    enum rawrtc_code error;

    // Check arguments
    if (!udp_helperp || !candidate_helper || !trace_handle) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Already attached?
    if (*udp_helperp) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Create receive handler context
    // TODO: When adding TCP support, local address may be different (as it's a separate socket)
    error = rawrtc_packet_trace_helper_context_create(
            &context, trace_handle, &candidate_helper->candidate->attr.addr, NULL);
    if (error) {
        goto out;
    }

    // Set receive handler on local host candidate
    error = set_receive_handler(
            &udp_helper, candidate_helper->gatherer->ice,
            candidate_helper->candidate, trace_layer, rawrtc_packet_trace_udp_outbound_handler,
            rawrtc_packet_trace_udp_inbound_handler, context);
    if (error) {
        goto out;
    }

    // Note: Applying the receive handler to local STUN session's candidates is not needed as they
    //       do not have a socket (they are tied to the host candidate's socket).

    // Note: Applying the receive handler to local TURN session's candidates is not needed as they
    //       do not have their own socket. This may change once we add TCP support.

out:
    if (error) {
        mem_deref(udp_helper);
        mem_deref(context);
    } else {
        // Add to list & set pointer
        list_append(&candidate_helper->trace_packet_helper_contexts, &context->le, context);
        *udp_helperp = udp_helper;
    }
    return error;
}

/*
 * Check whether a local re candidate is associated to a candidate helper.
 */
static bool is_candidate_associated_to_helper(
        struct rawrtc_candidate_helper* const candidate_helper,
        struct ice_lcand* const re_candidate
) {
    struct le* le;

    // Is local host candidate?
    if (candidate_helper->candidate == re_candidate) {
        return true;
    }

    // Is local srflx candidate?
    for (le = list_head(&candidate_helper->stun_sessions); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper_stun_session* const session = le->data;
        if (session->candidate == re_candidate) {
            return true;
        }
    }

    // Is local relay candidate?
    for (le = list_head(&candidate_helper->turn_sessions); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper_turn_session* const session = le->data;
        if (session->candidate == re_candidate) {
            return true;
        }
    }
}

/*
 * Find a specific candidate helper by re candidate.
 */
enum rawrtc_code rawrtc_candidate_helper_find(
        struct rawrtc_candidate_helper** const candidate_helperp,
        struct list* const candidate_helpers,
        struct ice_lcand* re_candidate
) {
    struct le* le;

    // Check arguments
    if (!candidate_helperp || !candidate_helpers || !re_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Lookup candidate helper
    for (le = list_head(candidate_helpers); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate_helper = le->data;
        if (is_candidate_associated_to_helper(candidate_helper, re_candidate)) {
            // Found
            *candidate_helperp = candidate_helper;
            return RAWRTC_CODE_SUCCESS;
        }
    }

    // Not found
    return RAWRTC_CODE_NO_VALUE;
}

static void rawrtc_candidate_helper_stun_session_destroy(
        void* arg
) {
    struct rawrtc_candidate_helper_stun_session* const session = arg;

    // Remove from list
    list_unlink(&session->le);

    // Un-reference
    mem_deref(session->url);
    mem_deref(session->stun_keepalive);
    mem_deref(session->candidate);
    mem_deref(session->candidate_helper);
}

/*
 * Create a STUN session.
 */
enum rawrtc_code rawrtc_candidate_helper_stun_session_create(
        struct rawrtc_candidate_helper_stun_session** const sessionp, // de-referenced
        struct rawrtc_ice_server_url* const url
) {
    struct rawrtc_candidate_helper_stun_session* session;

    // Check arguments
    if (!sessionp || !url) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    session = mem_zalloc(sizeof(*session), rawrtc_candidate_helper_stun_session_destroy);
    if (!session) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    session->url = mem_ref(url);

    // Set pointer & done
    *sessionp = session;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add a STUN session to a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_stun_session_add(
        struct rawrtc_candidate_helper_stun_session* const session,
        struct rawrtc_candidate_helper* const candidate_helper,
        struct stun_keepalive* const stun_keepalive
) {
    // Check arguments
    if (!session || !candidate_helper || !stun_keepalive) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields/reference
    session->candidate_helper = mem_ref(candidate_helper);
    session->stun_keepalive = mem_ref(stun_keepalive);

    // Append to STUN sessions
    list_append(&candidate_helper->stun_sessions, &session->le, session);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add a local re candidate to a STUN session.
 */
enum rawrtc_code rawrtc_candidate_helper_stun_session_add_candidate(
        struct rawrtc_candidate_helper_stun_session* const session,
        struct ice_lcand* const re_candidate
) {
    // Check arguments
    if (!session || !re_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Note: Applying the receive handler to the local srflx candidate is not needed as srflx
    //       candidates do not have a socket (they are tied to the local host candidate's socket).

    // Un-reference old candidate (if any)
    if (session->candidate) {
        DEBUG_WARNING("STUN session had a candidate before! Report this incident!\n");
        session->candidate = mem_deref(session->candidate);
    }

    // Reference & set candidate
    session->candidate = mem_ref(re_candidate);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

static void rawrtc_candidate_helper_turn_session_destroy(
        void* arg
) {
    struct rawrtc_candidate_helper_turn_session* const session = arg;

    // Remove from list
    list_unlink(&session->le);

    // Un-reference
    mem_deref(session->url);
    mem_deref(session->turn_client);
    mem_deref(session->candidate);
    mem_deref(session->candidate_helper);
}

/*
 * Create a TURN session.
 */
enum rawrtc_code rawrtc_candidate_helper_turn_session_create(
        struct rawrtc_candidate_helper_turn_session** const sessionp, // de-referenced
        struct rawrtc_ice_server_url* const url
) {
    struct rawrtc_candidate_helper_turn_session* session;

    // Check arguments
    if (!sessionp || !url) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    session = mem_zalloc(sizeof(*session), rawrtc_candidate_helper_turn_session_destroy);
    if (!session) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    session->url = mem_ref(url);

    // Set pointer & done
    *sessionp = session;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add a TURN session to a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_turn_session_add(
        struct rawrtc_candidate_helper_turn_session* const session,
        struct rawrtc_candidate_helper* const candidate_helper,
        struct turnc* const turn_client
) {
    // Check arguments
    if (!session || !candidate_helper || !turn_client) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields/reference
    session->candidate_helper = mem_ref(candidate_helper);
    session->turn_client = mem_ref(turn_client);

    // Append to TURN sessions
    list_append(&candidate_helper->turn_sessions, &session->le, session);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add a local re candidate to a TURN session.
 */
enum rawrtc_code rawrtc_candidate_helper_turn_session_add_candidate(
        struct rawrtc_candidate_helper_turn_session* const session,
        struct ice_lcand* const re_candidate
) {
    // Check arguments
    if (!session || !re_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Note: Applying the receive handler to the local relay candidate is not needed as relay
    //       candidates do not have their own socket. This may change once we add TCP support.

    // Un-reference old candidate (if any)
    if (session->candidate) {
        DEBUG_WARNING("TURN session had a candidate before! Report this incident!\n");
        session->candidate = mem_deref(session->candidate);
    }

    // Reference & set candidate
    session->candidate = mem_ref(re_candidate);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Remove all STUN and TURN sessions from a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_remove_sessions(
        struct list* const local_candidates
) {
    struct le* le;

    // Check arguments
    if (!local_candidates) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (le = list_head(local_candidates); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate_helper = le->data;

        // Flush TURN session
        list_flush(&candidate_helper->turn_sessions);

        // Flush STUN sessions
        list_flush(&candidate_helper->stun_sessions);
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Print debug information for a candidate helper.
 */
int rawrtc_candidate_helper_debug(
        struct re_printf* const pf,
        struct rawrtc_candidate_helper const* const candidate_helper
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!candidate_helper) {
        return 0;
    }

    err |= re_hprintf(pf, "  Candidate helper <%p>:\n", candidate_helper);

    // Associated host candidate
    err |= re_hprintf(pf, "    host_candidate=<%p>\n", candidate_helper->candidate);

    // STUN sessions
    err |= re_hprintf(pf, "    stun_sessions=%"PRIu32" pending=%"PRIu8"\n",
                      list_count(&candidate_helper->stun_sessions),
                      candidate_helper->srflx_pending_count);
    // Associated srflx candidates
    for (le = list_head(&candidate_helper->stun_sessions); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper_stun_session* const session = le->data;
        err |= re_hprintf(pf, "    srflx_candidate=<%p>\n", session->candidate);
    }

    // TURN sessions
    err |= re_hprintf(pf, "    turn_sessions=%"PRIu32" pending=%"PRIu8"\n",
                      list_count(&candidate_helper->turn_sessions),
                      candidate_helper->relay_pending_count);
    // Associated relay candidates
    for (le = list_head(&candidate_helper->turn_sessions); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper_turn_session* const session = le->data;
        err |= re_hprintf(pf, "    relay_candidate=<%p>\n", session->candidate);
    }

    // Done
    return err;
}
