#include "parameters.h"
#include <rawrtc/ice_parameters.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

/*
 * Destructor for an existing ICE parameters instance.
 */
static void rawrtc_ice_parameters_destroy(
        void* arg
) {
    struct rawrtc_ice_parameters* const parameters = arg;

    // Un-reference
    mem_deref(parameters->username_fragment);
    mem_deref(parameters->password);
}

/*
 * Create a new ICE parameters instance.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_create(
        struct rawrtc_ice_parameters** const parametersp, // de-referenced
        char* const username_fragment, // copied
        char* const password, // copied
        bool const ice_lite
) {
    struct rawrtc_ice_parameters* parameters;
    enum rawrtc_code error;

    // Check arguments
    if (!parametersp || !username_fragment || !password) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_zalloc(sizeof(*parameters), rawrtc_ice_parameters_destroy);
    if (!parameters) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    error = rawrtc_strdup(&parameters->username_fragment, username_fragment);
    if (error) {
        goto out;
    }
    error = rawrtc_strdup(&parameters->password, password);
    if (error) {
        goto out;
    }
    parameters->ice_lite = ice_lite;

out:
    if (error) {
        mem_deref(parameters);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}
