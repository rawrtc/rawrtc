#include <anyrtc.h>
#include "main.h"

/*
 * Initialise anyrtc. Must be called before making a call to any other
 * function
 */
enum anyrtc_code anyrtc_init() {
    // Initialise re
    if (libre_init()) {
        return ANYRTC_CODE_INITIALISE_FAIL;
    }
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Close anyrtc and free up all resources.
 */
enum anyrtc_code anyrtc_close() {
    // Close re
    libre_close();
    return ANYRTC_CODE_SUCCESS;
}
