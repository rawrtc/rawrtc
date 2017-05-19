#include <rawrtc_internal.h>
#include "data_channel_options.h"

/*
 * Create data channel options.
 *
 * - `deliver_partially`: Enable this if you want to receive partial
 *   messages. Disable if messages should arrive complete. If enabled,
 *   message chunks will be delivered until the message is complete.
 *   Other messages' chunks WILL NOT be interleaved on the same channel.
 */
enum rawrtc_code rawrtc_data_channel_options_create(
        struct rawrtc_data_channel_options** const optionsp, // de-referenced
        bool const deliver_partially
) {
    struct rawrtc_data_channel_options* options;

    // Check arguments
    if (!optionsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    options = mem_zalloc(sizeof(*options), NULL);
    if (!options) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    options->deliver_partially = deliver_partially;

    // Set pointer & done
    *optionsp = options;
    return RAWRTC_CODE_SUCCESS;
}
