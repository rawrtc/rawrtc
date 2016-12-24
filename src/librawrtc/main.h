#pragma once
#include <rawrtc.h>

enum rawrtc_code rawrtc_init();
enum rawrtc_code rawrtc_close();
void rawrtc_thread_enter();
void rawrtc_thread_leave();
