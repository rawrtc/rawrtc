#pragma once

enum anyrtc_code anyrtc_message_buffer_append(
    struct list* const message_buffer,
    struct mbuf* const buffer, // referenced
    void* const context // referenced, nullable
);

enum anyrtc_code anyrtc_message_buffer_clear(
    struct list* const message_buffer,
    anyrtc_message_buffer_handler* const message_handler,
    void* arg
);
