#pragma once

enum rawrtc_code rawrtc_data_channel_parameters_create_internal(
    struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
    char* const label, // referenced, nullable
    enum rawrtc_data_channel_type const channel_type,
    uint32_t const reliability_parameter,
    char* const protocol, // referenced, nullable
    bool const negotiated,
    uint16_t const id
);
