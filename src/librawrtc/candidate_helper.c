#include <rawrtc.h>
#include "candidate_helper.h"

/*
 * Destructor for an existing candidate helper.
 */
static void rawrtc_candidate_helper_destroy(
        void* const arg
) {
    struct rawrtc_candidate_helper* const candidate_helper = arg;

    // Dereference
    mem_deref(candidate_helper->helper);
    mem_deref(candidate_helper->candidate);
}

/*
 * Attach a candidate helper.
 */
enum rawrtc_code rawrtc_candidate_helper_attach(
        struct rawrtc_candidate_helper** const candidate_helperp, // de-referenced
        struct trice* const ice,
        struct ice_lcand* const candidate,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    struct rawrtc_candidate_helper* candidate_helper;
    enum rawrtc_code error;

    // Check arguments
    if (!candidate_helperp || !ice || !candidate || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate's UDP socket
    struct udp_sock* const udp_socket = trice_lcand_sock(ice, candidate);
    if (!udp_socket) {
        return RAWRTC_CODE_NO_SOCKET;
    }

    // Create DTLS candidate helper
    candidate_helper = mem_zalloc(sizeof(*candidate_helper), rawrtc_candidate_helper_destroy);
    if (!candidate_helper) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set candidate
    candidate_helper->candidate = mem_ref(candidate);

    // Create & attach UDP helper
    error = rawrtc_error_to_code(udp_register_helper(
            &candidate_helper->helper, udp_socket, RAWRTC_LAYER_DTLS_SRTP_STUN, NULL,
            receive_handler, arg));
    if (error) {
        goto out;
    }

    // TODO: What about TCP helpers?

out:
    if (error) {
        mem_deref(candidate_helper);
    } else {
        // Set pointer
        *candidate_helperp = candidate_helper;
    }
    return error;
}
