#include <rawrtc.h>
#include "ice_parameters.h"

/*
 * Print debug information for ICE parameters.
 */
int rawrtc_ice_parameters_debug(
        struct re_printf* const pf,
        struct rawrtc_ice_parameters const* const parameters
) {
    int err = 0;

    // Check arguments
    if (!parameters) {
        return 0;
    }

    err |= re_hprintf(pf, "  ICE Parameters <%p>:\n", parameters);

    // Username fragment
    err |= re_hprintf(pf, "    username_fragment=\"%s\"\n", parameters->username_fragment);

    // Password
    err |= re_hprintf(pf, "    password=\"%s\"\n", parameters->password);

    // ICE lite
    err |= re_hprintf(pf, "    ice_lite=%s\n", parameters->ice_lite ? "yes" : "no");

    // Done
    return err;
}

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
