#include <rawrtc.h>
#include "common.h"

/*
 * Ignore success code list.
 */
enum rawrtc_code const ignore_success[] = {RAWRTC_CODE_SUCCESS};
size_t const ignore_success_length =
        sizeof(ignore_success) / sizeof(ignore_success[0]);
