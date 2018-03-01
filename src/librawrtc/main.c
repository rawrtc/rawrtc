#include <rawrtc.h>
#include "main.h"

/*
 * Initialise rawrtc. Must be called before making a call to any other
 * function.
 *
 * Note: In case `init_re` is not set to `true`, you MUST initialise
 *       re yourselves before calling this function.
 */
enum rawrtc_code rawrtc_init(
        bool const init_re
) {
    // Initialise RAWRTCDC
    return rawrtcdc_init(init_re);
}

/*
 * Close rawrtc and free up all resources.
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
