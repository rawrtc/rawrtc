#pragma once

/*
 * Handle buffered messages.
 */
typedef void (rawrtc_message_buffer_handler)(
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
