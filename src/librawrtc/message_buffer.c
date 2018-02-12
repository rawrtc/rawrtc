#include <rawrtc.h>
#include "message_buffer.h"

#define DEBUG_MODULE "message-buffer"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Get the sum of bytes of all message buffer's left.
 */
size_t buffer_sum_left(
        struct list* const message_buffer // not checked
) {
    struct le* le;
    size_t size = 0;

    // Handle each message
    for (le = list_head(message_buffer); le != NULL; le = le->next) {
        struct rawrtc_buffered_message* const buffered_message = le->data;
        size += mbuf_get_left(buffered_message->buffer);
    }

    // Done
    return size;
}

/*
 * Destructor for an existing buffered message.
 */
static void rawrtc_message_buffer_destroy(
        void* arg
) {
    struct rawrtc_buffered_message* const buffered_message = arg;

    // Un-reference
    mem_deref(buffered_message->context);
    mem_deref(buffered_message->buffer);
}

/*
 * Create a message buffer.
 *
 * TODO: Add timestamp to be able to ignore old messages
 */
enum rawrtc_code rawrtc_message_buffer_append(
        struct list* const message_buffer,
        struct mbuf* const buffer, // referenced
        void* const context // referenced, nullable
) {
    struct rawrtc_buffered_message* buffered_message;

    // Check arguments
    if (!message_buffer || !buffer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create buffered message
    buffered_message = mem_zalloc(sizeof(*buffered_message), rawrtc_message_buffer_destroy);
    if (!buffered_message) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    buffered_message->buffer = mem_ref(buffer);
    buffered_message->context = mem_ref(context);

    // Add to list
    list_append(message_buffer, &buffered_message->le, buffered_message);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Apply a receive handler to buffered messages.
 *
 * Will stop iterating and return `RAWRTC_CODE_STOP_ITERATION` in case
 * the message handler returned `false`.
 */
enum rawrtc_code rawrtc_message_buffer_clear(
        struct list* const message_buffer,
        rawrtc_message_buffer_handler* const message_handler,
        void* arg
) {
    struct le* le;
    bool unlink;

    // Check arguments
    if (!message_buffer || !message_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Handle each message
    le = list_head(message_buffer);
    while (le != NULL) {
        struct rawrtc_buffered_message* const buffered_message = le->data;

        // Handle message
        unlink = message_handler(buffered_message->buffer, buffered_message->context, arg);
        if (unlink) {
            list_unlink(le);
        }

        // Get next message
        le = le->next;

        // Remove message
        if (unlink) {
            mem_deref(buffered_message);
        } else {
            return RAWRTC_CODE_STOP_ITERATION;
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Merge all buffered messages into a single buffer.
 *
 * If no message is present, both `bufferp`'s and `contextp`'s value
 * will be set to `NULL` and the return code will be
 * `RAWRTC_CODE_NO_VALUE`.
 *
 * In case all messages did not provide a buffer, `bufferp`'s value will
 * be set to `NULL` but `contextp`'s value will represent the context of
 * the fist message (which may also be `NULL`). The return code will be
 * `RAWRTC_CODE_SUCCESS`.
 *
 * Note: Only the first message's context will be returned.
 */
enum rawrtc_code rawrtc_message_buffer_merge(
        struct mbuf** const bufferp, // de-referenced
        void** const contextp, // de-referenced
        struct list* const message_buffer
) {
    struct le* le;
    struct rawrtc_buffered_message* buffered_message;
    void* context;
    struct mbuf* buffer = NULL;
    int err = 0;
    size_t pos;
    size_t end;

    // Check arguments
    if (!bufferp || !contextp || !message_buffer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get first message (or return none)
    le = list_head(message_buffer);
    if (!le) {
        DEBUG_PRINTF("Nothing to merge\n");
        *bufferp = NULL;
        *contextp = NULL;
        return RAWRTC_CODE_NO_VALUE;
    }

    // Get context from first message
    buffered_message = le->data;
    context = buffered_message->context;

    DEBUG_PRINTF("Merging %zu buffered messages\n", list_count(message_buffer));

    // Handle each message
    for (; le != NULL; le = le->next) {
        buffered_message = le->data;

        // Get buffer (if not already set)
        if (!buffer) {
            if (buffered_message->buffer) {
                // Set buffer & resize to sum of all buffers
                buffer = buffered_message->buffer;
                pos = buffer->pos;
                end = buffer->end;
                err = mbuf_resize(buffer, pos + buffer_sum_left(message_buffer));
                if (err) {
                    goto out;
                }

                DEBUG_PRINTF("Resized buffer to %zu bytes\n", buffer->size);

                // Skip to end (needed to use `mbuf_write_mem` for merging)
                mbuf_skip_to_end(buffer);
            }

            // Skip copying
            continue;
        }

        // Copy data (if any)
        if (buffered_message->buffer) {
            err = mbuf_write_mem(buffer, mbuf_buf(buffered_message->buffer),
                                 mbuf_get_left(buffered_message->buffer));
            if (err) {
                goto out;
            }
        }
    }

out:
    if (buffer) {
        // Reset position
        mbuf_set_pos(buffer, pos);
    }

    if (err) {
        if (buffer) {
            // Reset end
            mbuf_set_end(buffer, end);

            // Undo resize
            mbuf_trim(buffer);
            DEBUG_PRINTF("Resized buffer back to %zu bytes due to error\n", buffer->size);
        }
    } else {
        // Set pointer
        *bufferp = mem_ref(buffer);
        *contextp = mem_ref(context);

        // Un-reference all messages
        list_flush(message_buffer);
        DEBUG_PRINTF("Merging complete\n");
    }

    return rawrtc_error_to_code(err);
}
