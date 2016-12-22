#pragma once

void anyrtc_data_channel_set_state(
    struct anyrtc_data_channel* const channel,
    enum anyrtc_data_channel_state const state
);

enum anyrtc_code anyrtc_data_transport_create(
    struct anyrtc_data_transport** const transportp, // de-referenced
    enum anyrtc_data_transport_type const type,
    void* const internal_transport, // referenced
    anyrtc_data_transport_channel_create_handler* const channel_create_handler,
    anyrtc_data_transport_channel_close_handler* const channel_close_handler,
    anyrtc_data_transport_channel_send_handler* const channel_send_handler
);
