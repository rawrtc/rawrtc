#include <anyrtc.h>
#include "dtls_parameters.h"

/*
 * Destructor for an existing DTLS fingerprint instance.
 */
static void anyrtc_dtls_fingerprint_destroy(
        void* const arg
) {
    struct anyrtc_dtls_fingerprint* const fingerprint = arg;

    // Dereference
    mem_deref(fingerprint->value);
}

/*
 * Create a new DTLS fingerprint instance.
 */
enum anyrtc_code anyrtc_dtls_fingerprint_create(
        struct anyrtc_dtls_fingerprint** const fingerprintp, // de-referenced
        enum anyrtc_certificate_sign_algorithm const algorithm,
        char* const value // copied
) {
    struct anyrtc_dtls_fingerprint* fingerprint;
    enum anyrtc_code error;

    // Allocate
    fingerprint = mem_zalloc(sizeof(struct anyrtc_dtls_fingerprint),
                             anyrtc_dtls_fingerprint_destroy);
    if (!fingerprint) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    fingerprint->algorithm = algorithm;
    error = anyrtc_strdup(&fingerprint->value, value);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(fingerprint);
    } else {
        // Set pointer
        *fingerprintp = fingerprint;
    }
    return error;
}

/*
 * Create a new DTLS fingerprint instance without any value.
 * The caller MUST set the `value` field after creation.
 */
enum anyrtc_code anyrtc_dtls_fingerprint_create_empty(
        struct anyrtc_dtls_fingerprint** const fingerprintp, // de-referenced
        enum anyrtc_certificate_sign_algorithm const algorithm
) {
    struct anyrtc_dtls_fingerprint* fingerprint;

    // Allocate
    fingerprint = mem_zalloc(sizeof(struct anyrtc_dtls_fingerprint),
                             anyrtc_dtls_fingerprint_destroy);
    if (!fingerprint) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    fingerprint->algorithm = algorithm;

    // Set pointer
    *fingerprintp = fingerprint;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing DTLS parameters instance.
 */
static void anyrtc_dtls_parameters_destroy(
        void* const arg
) {
    struct anyrtc_dtls_parameters* const parameters = arg;

    // Dereference
    list_flush(&parameters->fingerprints);
}

/*
 * Create a new DTLS parameters instance.
 */
enum anyrtc_code anyrtc_dtls_parameters_create(
        struct anyrtc_dtls_parameters** const parametersp, // de-referenced
        enum anyrtc_dtls_role const role,
        struct anyrtc_dtls_fingerprint* const fingerprints[], // copied (each item)
        size_t const n_fingerprints
) {
    struct anyrtc_dtls_parameters* parameters;
    size_t i;
    struct anyrtc_dtls_fingerprint* fingerprint;
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;

    // Check arguments
    if (!parametersp || !role || !fingerprints || n_fingerprints < 1) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_zalloc(sizeof(struct anyrtc_dtls_parameters), anyrtc_dtls_parameters_destroy);
    if (!parameters) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set role
    parameters->role = role;

    // Copy and append each fingerprint
    for (i = 0; i < n_fingerprints; ++i) {
        // Check algorithm
        if (fingerprints[i]->algorithm == ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Copy fingerprint
        // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
        error = anyrtc_dtls_fingerprint_create(
                &fingerprint, fingerprints[i]->algorithm, fingerprints[i]->value);
        if (error) {
            goto out;
        }

        // Append to list
        list_append(&parameters->fingerprints, &fingerprint->le, fingerprint);
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
enum anyrtc_code anyrtc_dtls_parameters_create_internal(
        struct anyrtc_dtls_parameters** const parametersp, // de-referenced
        enum anyrtc_dtls_role const role,
        struct list* const fingerprints
) {
    struct le* le;
    struct anyrtc_dtls_parameters* parameters;
    struct anyrtc_dtls_fingerprint* copied_fingerprint;
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;

    // Check arguments
    if (!parametersp || !fingerprints) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_zalloc(sizeof(struct anyrtc_dtls_parameters), anyrtc_dtls_parameters_destroy);
    if (!parameters) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set role
    parameters->role = role;

    // Copy and append each fingerprint
    for (le = list_head(fingerprints); le != NULL; le = le->next) {
        struct anyrtc_dtls_fingerprint* const fingerprint = le->data;

        // Check algorithm
        if (fingerprint->algorithm == ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Copy fingerprint
        // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
        error = anyrtc_dtls_fingerprint_create(
                &copied_fingerprint, fingerprint->algorithm, fingerprint->value);
        if (error) {
            goto out;
        }

        // Append to list
        list_append(&parameters->fingerprints, &copied_fingerprint->le, copied_fingerprint);
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
 * Get the DTLS parameter's role value.
 */
enum anyrtc_code anyrtc_dtls_parameters_get_role(
        enum anyrtc_dtls_role* rolep, // de-referenced
        struct anyrtc_dtls_parameters* const parameters
) {
    // Check arguments
    if (!rolep || !parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *rolep = parameters->role;
    return ANYRTC_CODE_SUCCESS;
}
