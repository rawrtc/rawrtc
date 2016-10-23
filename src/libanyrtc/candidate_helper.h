#pragma once

enum anyrtc_code anyrtc_candidate_helper_attach(
    struct anyrtc_candidate_helper** const candidate_helperp, // de-referenced
    struct trice* const ice,
    struct ice_lcand* const candidate,
    udp_helper_recv_h* const receive_handler,
    void* const arg
);

enum anyrtc_code anyrtc_candidate_helper_buffer_message(
    struct list* const buffered_messages,
    struct sa * const source, // copied, nullable
    struct mbuf* const buffer // referenced
);

enum anyrtc_code anyrtc_candidate_helper_handle_buffered_messages(
    struct list* const buffered_messages,
    udp_helper_recv_h* const receive_handler,
    void* arg
);
