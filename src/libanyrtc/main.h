#pragma once
#include <anyrtc.h>

enum anyrtc_code anyrtc_init();
enum anyrtc_code anyrtc_close();
void anyrtc_thread_enter();
void anyrtc_thread_leave();
