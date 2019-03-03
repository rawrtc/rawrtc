#include "parameters.h"
#include <rawrtc/ice_parameters.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Get the ICE parameter's username fragment value.
 * `*username_fragmentp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_username_fragment(
        char** const username_fragmentp, // de-referenced
        struct rawrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!username_fragmentp || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *username_fragmentp = mem_ref(parameters->username_fragment);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the ICE parameter's password value.
 * `*passwordp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_password(
        char** const passwordp, // de-referenced
        struct rawrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!passwordp || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *passwordp = mem_ref(parameters->password);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the ICE parameter's ICE lite value.
 */
enum rawrtc_code rawrtc_ice_parameters_get_ice_lite(
        bool* const ice_litep, // de-referenced
        struct rawrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!ice_litep || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *ice_litep = parameters->ice_lite;
    return RAWRTC_CODE_SUCCESS;
}
