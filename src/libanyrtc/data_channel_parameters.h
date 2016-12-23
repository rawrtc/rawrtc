#pragma once

enum anyrtc_code anyrtc_data_channel_parameters_create_internal(
    struct anyrtc_data_channel_parameters** const parametersp, // de-referenced
    char* const label, // referenced, nullable
    enum anyrtc_data_channel_type const channel_type,
    uint32_t const reliability_parameter,
    char* const protocol, // referenced, nullable
    bool const negotiated,
    uint16_t const id
);
