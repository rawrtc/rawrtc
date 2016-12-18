#pragma once

enum anyrtc_code anyrtc_data_transport_create(
    struct anyrtc_data_transport** const transportp, // de-referenced
    enum anyrtc_data_transport_type type,
    void* const internal_transport
);
