#pragma once
#include <rawrtc.h>

enum rawrtc_code rawrtc_data_transport_create(
    struct rawrtc_data_transport** const transportp, // de-referenced
    enum rawrtc_data_transport_type const type,
    void* const internal_transport, // referenced
    rawrtc_data_transport_channel_create_handler* const channel_create_handler,
    rawrtc_data_transport_channel_close_handler* const channel_close_handler,
    rawrtc_data_transport_channel_send_handler* const channel_send_handler
);
