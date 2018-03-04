#include <rawrtc.h>
#include "main.h"

#define DEBUG_MODULE "rawrtc-main"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

struct rawrtc_global rawrtc_global;

/*
 * Handle RAWRTCDC timer tick expired.
 */
static inline void rawrtcdc_timer_tick_expired_handler(
        void* arg
) {
    (void) arg;

    // Restart timer
    tmr_start(&rawrtc_global.rawrtcdc_timer, (uint64_t) rawrtc_global.rawrtcdc_timer_interval,
              rawrtcdc_timer_tick_expired_handler, NULL);

    // Handle timer tick
    rawrtcdc_timer_tick(rawrtc_global.rawrtcdc_timer_interval);
}

/*
 * RAWRTCDC timer handler.
 */
static inline enum rawrtc_code rawrtcdc_timer_tick_handler(
        bool const on,
        uint_fast16_t const interval
) {
    // Start or stop timer?
    if (on) {
        // Store interval, initialise & start timer
        rawrtc_global.rawrtcdc_timer_interval = interval;
        tmr_start(&rawrtc_global.rawrtcdc_timer, (uint64_t) rawrtc_global.rawrtcdc_timer_interval,
                  rawrtcdc_timer_tick_expired_handler, NULL);
        DEBUG_PRINTF("Started RAWRTCDC timer\n");
    } else {
        tmr_cancel(&rawrtc_global.rawrtcdc_timer);
        DEBUG_PRINTF("Stopped RAWRTCDC timer\n");
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Initialise RAWRTC. Must be called before making a call to any other
 * function.
 *
 * Note: In case `init_re` is not set to `true`, you MUST initialise
 *       re yourselves before calling this function.
 */
enum rawrtc_code rawrtc_init(
        bool const init_re
) {
    // Initialise timer
    tmr_init(&rawrtc_global.rawrtcdc_timer);

    // Initialise RAWRTCDC
    return rawrtcdc_init(init_re, rawrtcdc_timer_tick_handler);
}

/*
 * Close RAWRTC and free up all resources.
 *
 * Note: In case `close_re` is not set to `true`, you MUST close
 *       re yourselves.
 */
enum rawrtc_code rawrtc_close(
        bool const close_re
) {
    // Close RAWRTCDC
    return rawrtcdc_close(close_re);
}
