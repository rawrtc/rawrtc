#include <anyrtc.h>
#include "candidate_helper.h"

#define DEBUG_MODULE "helper"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Destructor for an existing candidate helper.
 */
static void anyrtc_candidate_helper_destroy(
        void* const arg
) {
    struct anyrtc_candidate_helper* const candidate_helper = arg;

    // Dereference
    mem_deref(candidate_helper->helper);
    mem_deref(candidate_helper->candidate);
}

/*
 * Attach a candidate helper.
 */
enum anyrtc_code anyrtc_candidate_helper_attach(
        struct anyrtc_candidate_helper** const candidate_helperp, // de-referenced
        struct trice* const ice,
        struct ice_lcand* const candidate,
        udp_helper_recv_h* const receive_handler,
        void* const arg
) {
    struct anyrtc_candidate_helper* candidate_helper;
    enum anyrtc_code error;

    // Check arguments
    if (!candidate_helperp || !ice || !candidate || !receive_handler) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate's UDP socket
    struct udp_sock* const udp_socket = trice_lcand_sock(ice, candidate);
    if (!udp_socket) {
        return ANYRTC_CODE_NO_SOCKET;
    }

    // Create DTLS candidate helper
    candidate_helper = mem_zalloc(sizeof(struct anyrtc_candidate_helper),
                                  anyrtc_candidate_helper_destroy);
    if (!candidate_helper) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set candidate
    candidate_helper->candidate = mem_ref(candidate);

    // Create & attach UDP helper
    error = anyrtc_translate_re_code(udp_register_helper(
            &candidate_helper->helper, udp_socket, ANYRTC_LAYER_DTLS, NULL,
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

/*
 * Destructor for an existing buffered message.
 */
static void anyrtc_buffered_message_destroy(
        void* const arg
) {
    struct anyrtc_buffered_message* const buffered_message = arg;

    // Dereference
    mem_deref(buffered_message->buffer);
}

/*
 * Create a candidate helper message buffer.
 */
enum anyrtc_code anyrtc_candidate_helper_buffer_message(
        struct list* const buffered_messages,
        struct sa * const source, // copied
        struct mbuf* const buffer // referenced
) {
    struct anyrtc_buffered_message* buffered_message;

    // Check arguments
    if (!buffered_messages || !source || !buffer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create buffered message
    buffered_message = mem_zalloc(sizeof(struct anyrtc_buffered_message),
                                  anyrtc_buffered_message_destroy);
    if (!buffered_message) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    buffered_message->source = *source;
    buffered_message->buffer = mem_ref(buffer);

    // Add to list
    list_append(buffered_messages, &buffered_message->le, buffered_message);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Apply a receive handler to buffered messages.
 */
enum anyrtc_code anyrtc_candidate_helper_handle_buffered_messages(
        struct list* const buffered_messages,
        udp_helper_recv_h* const receive_handler,
        void* arg
) {
    struct le* le;

    // Check arguments
    if (!buffered_messages || !receive_handler) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Receive each message
    for (le = list_head(buffered_messages); le != NULL; le = le->next) {
        struct anyrtc_buffered_message* const buffered_message = le->data;

        // Receive buffered message
        receive_handler(&buffered_message->source, buffered_message->buffer, arg);
    }

    // Dereference all messages
    list_flush(buffered_messages);

    // Done
    return ANYRTC_CODE_SUCCESS;
}
