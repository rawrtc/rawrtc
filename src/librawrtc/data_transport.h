#pragma once

/*
 * Data channel flags.
 */
enum {
    RAWRTC_DATA_CHANNEL_FLAGS_INITIALIZED = 1 << 0,
    RAWRTC_DATA_CHANNEL_FLAGS_CAN_SET_OPTIONS = 1 << 1,
};

void rawrtc_data_channel_set_state(
    struct rawrtc_data_channel* const channel,
    enum rawrtc_data_channel_state const state
);

enum rawrtc_code rawrtc_data_transport_create(
    struct rawrtc_data_transport** const transportp, // de-referenced
    enum rawrtc_data_transport_type const type,
    void* const internal_transport, // referenced
    rawrtc_data_transport_channel_create_handler* const channel_create_handler,
    rawrtc_data_transport_channel_close_handler* const channel_close_handler,
    rawrtc_data_transport_channel_send_handler* const channel_send_handler
);

enum rawrtc_code rawrtc_data_channel_create_internal(
    struct rawrtc_data_channel** const channelp, // de-referenced
    struct rawrtc_data_transport* const transport, // referenced
    struct rawrtc_data_channel_parameters* const parameters, // referenced
    struct rawrtc_data_channel_options* options, // nullable, referenced
    rawrtc_data_channel_open_handler* const open_handler, // nullable
    rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
    rawrtc_data_channel_error_handler* const error_handler, // nullable
    rawrtc_data_channel_close_handler* const close_handler, // nullable
    rawrtc_data_channel_message_handler* const message_handler, // nullable
    void* const arg, // nullable
    bool const call_handler
);

void rawrtc_data_channel_call_channel_handler(
    struct rawrtc_data_channel* const channel, // not checked
    rawrtc_data_channel_handler* const channel_handler, // nullable
    void* const arg
);
