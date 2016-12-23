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

enum anyrtc_code anyrtc_data_channel_create_internal(
    struct anyrtc_data_channel** const channelp, // de-referenced
    struct anyrtc_data_transport* const transport, // referenced
    struct anyrtc_data_channel_parameters* const parameters, // referenced
    anyrtc_data_channel_open_handler* const open_handler, // nullable
    anyrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    anyrtc_data_channel_error_handler* const error_handler, // nullable
    anyrtc_data_channel_close_handler* const close_handler, // nullable
    anyrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg, // nullable
    bool const call_handler
);
