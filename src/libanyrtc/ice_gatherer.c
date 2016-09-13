#include <anyrtc.h>
#include "ice_gatherer.h"

static void anyrtc_ice_gather_options_destroy(void *arg)
{
    struct anyrtc_ice_gather_options* options = arg;

    // Dereference
    list_flush(&options->ice_servers);
}

/*
 * Create a new ICE gather options.
 * @optionsp Must be a valid address.
 */
enum anyrtc_code anyrtc_ice_gather_options_create(
        struct anyrtc_ice_gather_options** const optionsp, // de-referenced
        enum anyrtc_ice_gather_policy const gather_policy
) {
    struct anyrtc_ice_gather_options* options;

    if (!optionsp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    options = mem_alloc(sizeof(struct anyrtc_ice_gather_options), anyrtc_ice_gather_options_destroy);
    if (!options) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    options->gather_policy = gather_policy;
    list_init(&options->ice_servers);

    *optionsp = options;
    return ANYRTC_CODE_SUCCESS;
}
