#pragma once
#include <rawrtc_internal.h>

/*
 * Global rawrtc vars.
 */
struct rawrtc_global {
    pthread_mutex_t mutex;
    pthread_t mutex_main_thread;
    uint_fast16_t mutex_counter;
    uint_fast32_t usrsctp_initialized;
    struct tmr usrsctp_tick_timer;
    size_t usrsctp_chunk_size;
};

extern struct rawrtc_global rawrtc_global;

void rawrtc_thread_enter();
void rawrtc_thread_leave();
