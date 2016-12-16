#include <anyrtc.h>
#include "ice_parameters.h"

/*
 * Destructor for an existing ICE parameters instance.
 */
static void anyrtc_ice_parameters_destroy(
        void* const arg
) {
    struct anyrtc_ice_parameters* const parameters = arg;

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
    parameters = mem_zalloc(sizeof(*parameters), anyrtc_ice_parameters_destroy);
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
        mem_deref(parameters);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}

/*
 * Get the ICE parameter's username fragment value.
 * `*username_fragmentp` must be unreferenced.
 */
enum anyrtc_code anyrtc_ice_parameters_get_username_fragment(
        char** const username_fragmentp, // de-referenced
        struct anyrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!username_fragmentp || !parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *username_fragmentp = mem_ref(parameters->username_fragment);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the ICE parameter's password value.
 * `*passwordp` must be unreferenced.
 */
enum anyrtc_code anyrtc_ice_parameters_get_password(
        char** const passwordp, // de-referenced
        struct anyrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!passwordp || !parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *passwordp = mem_ref(parameters->password);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the ICE parameter's ICE lite value.
 */
enum anyrtc_code anyrtc_ice_parameters_get_ice_lite(
        bool* const ice_litep, // de-referenced
        struct anyrtc_ice_parameters* const parameters
) {
    // Check arguments
    if (!ice_litep || !parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *ice_litep = parameters->ice_lite;
    return ANYRTC_CODE_SUCCESS;
}
