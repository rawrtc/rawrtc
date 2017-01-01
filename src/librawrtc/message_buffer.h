#pragma once

/*
 * Handle buffered messages.
 *
 * Return `true` if the message has been handled successfully and can
 * be unliked, `false` to stop processing messages and keep the current
 * message in the list.
 */
typedef bool (rawrtc_message_buffer_handler)(
    struct mbuf* const buffer,
    void* const context,
    void* const arg
);

enum rawrtc_code rawrtc_message_buffer_append(
    struct list* const message_buffer,
    struct mbuf* const buffer, // referenced
    void* const context // referenced, nullable
);

enum rawrtc_code rawrtc_message_buffer_clear(
    struct list* const message_buffer,
    rawrtc_message_buffer_handler* const message_handler,
    void* arg
);

enum rawrtc_code rawrtc_message_buffer_merge(
    struct mbuf** const bufferp, // de-referenced
    void** const contextp, // de-referenced
    struct list* const message_buffer
);
