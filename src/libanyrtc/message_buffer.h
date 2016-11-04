#pragma once

enum anyrtc_code anyrtc_message_buffer_append(
    struct list* const buffered_messages,
    struct sa * const source, // copied, nullable
    struct mbuf* const buffer // referenced
);

enum anyrtc_code anyrtc_message_buffer_clear(
    struct list* const message_buffer,
    udp_helper_recv_h* const receive_handler,
    void* arg
);
