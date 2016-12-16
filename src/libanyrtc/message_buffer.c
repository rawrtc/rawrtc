#include <anyrtc.h>
#include "message_buffer.h"

/*
 * Destructor for an existing buffered message.
 */
static void anyrtc_message_buffer_destroy(
        void* const arg
) {
    struct anyrtc_buffered_message* const buffered_message = arg;

    // Dereference
    mem_deref(buffered_message->context);
    mem_deref(buffered_message->buffer);
}

/*
 * Create a message buffer.
 */
enum anyrtc_code anyrtc_message_buffer_append(
        struct list* const message_buffer,
        struct mbuf* const buffer, // referenced
        void* const context // referenced, nullable
) {
    struct anyrtc_buffered_message* buffered_message;

    // Check arguments
    if (!message_buffer || !buffer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create buffered message
    buffered_message = mem_zalloc(sizeof(*buffered_message), anyrtc_message_buffer_destroy);
    if (!buffered_message) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    buffered_message->buffer = mem_ref(buffer);
    if (context) {
        buffered_message->context = mem_ref(context);
    }

    // Add to list
    list_append(message_buffer, &buffered_message->le, buffered_message);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Apply a receive handler to buffered messages.
 * TODO: Add timestamp to be able to ignore old messages
 */
enum anyrtc_code anyrtc_message_buffer_clear(
        struct list* const message_buffer,
        anyrtc_message_buffer_handler* const message_handler,
        void* arg
) {
    struct le* le;

    // Check arguments
    if (!message_buffer || !message_handler) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Handle each message
    for (le = list_head(message_buffer); le != NULL; le = le->next) {
        struct anyrtc_buffered_message* const buffered_message = le->data;

        // Handle buffered message
        message_handler(buffered_message->buffer, buffered_message->context, arg);
    }

    // Dereference all messages
    list_flush(message_buffer);

    // Done
    return ANYRTC_CODE_SUCCESS;
}
