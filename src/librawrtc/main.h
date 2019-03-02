#pragma once
#include <rawrtc.h>

extern struct rawrtc_global rawrtc_global;

/*
 * Global RAWRTC vars.
 */
struct rawrtc_global {
    struct tmr rawrtcdc_timer;
    uint_fast16_t rawrtcdc_timer_interval;
};
