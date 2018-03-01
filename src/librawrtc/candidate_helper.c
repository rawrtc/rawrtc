#include <rawrtc.h>
#include "ice_gatherer.h"
#include "candidate_helper.h"

/*
 * Destructor for an existing candidate helper.
 */
static void rawrtc_candidate_helper_destroy(
        void* arg
) {
    struct rawrtc_candidate_helper* const local_candidate = arg;

    // Un-reference
    list_flush(&local_candidate->stun_sessions);
    mem_deref(local_candidate->udp_helper);
    mem_deref(local_candidate->candidate);
    mem_deref(local_candidate->gatherer);
}

/*
 * Create a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_create(
        struct rawrtc_candidate_helper** const candidate_helperp, // de-referenced
        struct rawrtc_ice_gatherer* gatherer,
        struct ice_lcand* const candidate,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    struct rawrtc_candidate_helper* candidate_helper;
    enum rawrtc_code error;

    // Check arguments
    if (!candidate_helperp || !gatherer || !candidate || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create candidate helper
    candidate_helper = mem_zalloc(sizeof(*candidate_helper), rawrtc_candidate_helper_destroy);
    if (!candidate_helper) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    candidate_helper->gatherer = mem_ref(gatherer);
    candidate_helper->candidate = mem_ref(candidate);
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
 * Set a candidate helper's receive handler.
 */
enum rawrtc_code rawrtc_candidate_helper_set_receive_handler(
        struct rawrtc_candidate_helper* const candidate_helper,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    enum rawrtc_code error;
    struct udp_helper* udp_helper;

    // Check arguments
    if (!candidate_helper || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate's UDP socket
    struct udp_sock* const udp_socket = trice_lcand_sock(
            candidate_helper->gatherer->ice, candidate_helper->candidate);
    if (!udp_socket) {
        return RAWRTC_CODE_NO_SOCKET;
    }

    // Create UDP helper
    error = rawrtc_error_to_code(udp_register_helper(
            &udp_helper, udp_socket, RAWRTC_LAYER_DTLS_SRTP_STUN, NULL,
            receive_handler, arg));
    if (error) {
        return error;
    }

    // Unset current helper (if any) and set new helper
    mem_deref(candidate_helper->udp_helper);
    candidate_helper->udp_helper = udp_helper;

    // TODO: What about TCP helpers?

    // Done
    return RAWRTC_CODE_SUCCESS;
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
        if (candidate_helper->candidate == re_candidate) {
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
 * Remove STUN sessions list handler (for candidate helper lists).
 */
bool rawrtc_candidate_helper_remove_stun_sessions_handler(
        struct le* le,
        void* arg
) {
    struct rawrtc_candidate_helper* const candidate_helper = le->data;
    (void) arg;

    // Flush STUN sessions
    list_flush(&candidate_helper->stun_sessions);

    return false; // continue traversing
}
