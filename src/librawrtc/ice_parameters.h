#pragma once
#include <rawrtc.h>

struct rawrtc_ice_parameters {
    char* username_fragment; // copied
    char* password; // copied
    bool ice_lite;
};

int rawrtc_ice_parameters_debug(
    struct re_printf* const pf,
    struct rawrtc_ice_parameters const* const parameters
);
