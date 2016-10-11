#include <anyrtc.h>
#include "utils.h"
#include "ice_parameters.h"

/*
 * Destructor for an existing ICE parameters instance.
 */
static void anyrtc_ice_parameters_destroy(void* arg) {
    struct anyrtc_ice_parameters* parameters = arg;

    // Dereference
    mem_deref(parameters->username_fragment);
    mem_deref(parameters->password);
}

/*
 * Create a new ICE parameters instance.
 */
enum anyrtc_code anyrtc_ice_parameters_create(
        struct anyrtc_ice_parameters** const parametersp, // de-referenced
        char* const username_fragment, // copied
        char* const password, // copied
        bool const ice_lite
) {
    struct anyrtc_ice_parameters* parameters;
    enum anyrtc_code error;

    // Check arguments
    if (!parametersp || !username_fragment || !password) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_alloc(sizeof(struct anyrtc_ice_parameters), anyrtc_ice_parameters_destroy);
    if (!parameters) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    error = anyrtc_strdup(&parameters->username_fragment, username_fragment);
    if (error) {
        goto out;
    }
    error = anyrtc_strdup(&parameters->password, password);
    if (error) {
        goto out;
    }
    parameters->ice_lite = ice_lite;

    out:
    if (error) {
        mem_deref(parameters->username_fragment);
        mem_deref(parameters->password);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}
