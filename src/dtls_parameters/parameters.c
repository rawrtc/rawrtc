#include "parameters.h"
#include "../dtls_fingerprint/fingerprint.h"
#include <rawrtc/certificate.h>
#include <rawrtc/dtls_parameters.h>
#include <rawrtc/dtls_transport.h>
#include <re.h>

/*
 * Destructor for an existing DTLS parameter's fingerprints instance.
 */
static void rawrtc_dtls_parameters_fingerprints_destroy(void* arg) {
    struct rawrtc_dtls_fingerprints* const fingerprints = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        mem_deref(fingerprints->fingerprints[i]);
    }
}

/*
 * Destructor for an existing DTLS parameters instance.
 */
static void rawrtc_dtls_parameters_destroy(void* arg) {
    struct rawrtc_dtls_parameters* const parameters = arg;

    // Un-reference
    mem_deref(parameters->fingerprints);
}

/*
 * Common code to allocate a DTLS parameters instance.
 */
static enum rawrtc_code rawrtc_dtls_parameters_allocate(
    struct rawrtc_dtls_parameters** const parametersp,  // de-referenced
    enum rawrtc_dtls_role const role,
    size_t const n_fingerprints) {
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct rawrtc_dtls_parameters* parameters;
    size_t fingerprints_size;

    // Allocate parameters
    parameters = mem_zalloc(sizeof(*parameters), rawrtc_dtls_parameters_destroy);
    if (!parameters) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set role
    parameters->role = role;

    // Allocate fingerprints array & set length immediately
    fingerprints_size = sizeof(*parameters) * n_fingerprints;
    parameters->fingerprints = mem_zalloc(
        sizeof(*parameters) + fingerprints_size, rawrtc_dtls_parameters_fingerprints_destroy);
    if (!parameters->fingerprints) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }
    parameters->fingerprints->n_fingerprints = n_fingerprints;

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
 * Create a new DTLS parameters instance.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_create(
    struct rawrtc_dtls_parameters** const parametersp,  // de-referenced
    enum rawrtc_dtls_role const role,
    struct rawrtc_dtls_fingerprint* const fingerprints[],  // referenced (each item)
    size_t const n_fingerprints) {
    struct rawrtc_dtls_parameters* parameters;
    enum rawrtc_code error;
    size_t i;

    // Check arguments
    if (!parametersp || !fingerprints || n_fingerprints < 1) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create parameters
    error = rawrtc_dtls_parameters_allocate(&parameters, role, n_fingerprints);
    if (error) {
        goto out;
    }

    // Reference and set each fingerprint
    for (i = 0; i < n_fingerprints; ++i) {
        // Null?
        if (!fingerprints[i]) {
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Check algorithm
        if (fingerprints[i]->algorithm == RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Reference and set fingerprint
        parameters->fingerprints->fingerprints[i] = mem_ref(fingerprints[i]);
    }

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
 * Create parameters from the internal vars of a DTLS transport
 * instance.
 */
enum rawrtc_code rawrtc_dtls_parameters_create_internal(
    struct rawrtc_dtls_parameters** const parametersp,  // de-referenced
    enum rawrtc_dtls_role const role,
    struct list* const fingerprints) {
    size_t n_fingerprints;
    struct rawrtc_dtls_parameters* parameters;
    enum rawrtc_code error;
    struct le* le;
    size_t i;

    // Check arguments
    if (!parametersp || !fingerprints) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get fingerprints length
    n_fingerprints = list_count(fingerprints);

    // Create parameters
    error = rawrtc_dtls_parameters_allocate(&parameters, role, n_fingerprints);
    if (error) {
        goto out;
    }

    // Reference and set each fingerprint
    for (le = list_head(fingerprints), i = 0; le != NULL; le = le->next, ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint = le->data;

        // Check algorithm
        if (fingerprint->algorithm == RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Reference and set fingerprint
        parameters->fingerprints->fingerprints[i] = mem_ref(fingerprint);
    }

out:
    if (error) {
        mem_deref(parameters);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}
