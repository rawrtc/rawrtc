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
    fingerprint = mem_zalloc(sizeof(*fingerprint), anyrtc_dtls_fingerprint_destroy);
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
    fingerprint = mem_zalloc(sizeof(*fingerprint), anyrtc_dtls_fingerprint_destroy);
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
 * Destructor for an existing DTLS parameter's fingerprints instance.
 */
static void anyrtc_dtls_parameters_fingerprints_destroy(
        void* const arg
) {
    struct anyrtc_dtls_fingerprints* const fingerprints = arg;
    size_t i;

    // Dereference each item
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        mem_deref(fingerprints->fingerprints[i]);
    }
}

/*
 * Destructor for an existing DTLS parameters instance.
 */
static void anyrtc_dtls_parameters_destroy(
        void* const arg
) {
    struct anyrtc_dtls_parameters* const parameters = arg;

    // Dereference
    mem_deref(parameters->fingerprints);
}

/*
 * Common code to allocate a DTLS parameters instance.
 */
static enum anyrtc_code anyrtc_dtls_parameters_allocate(
        struct anyrtc_dtls_parameters** const parametersp, // de-referenced
        enum anyrtc_dtls_role const role,
        size_t const n_fingerprints
) {
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;
    struct anyrtc_dtls_parameters* parameters;
    size_t fingerprints_size;

    // Allocate parameters
    parameters = mem_zalloc(sizeof(*parameters), anyrtc_dtls_parameters_destroy);
    if (!parameters) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set role
    parameters->role = role;

    // Allocate fingerprints array & set length immediately
    fingerprints_size = sizeof(*parameters) * n_fingerprints;
    parameters->fingerprints = mem_zalloc(sizeof(*parameters) + fingerprints_size,
                                          anyrtc_dtls_parameters_fingerprints_destroy);
    if (!parameters->fingerprints) {
        error = ANYRTC_CODE_NO_MEMORY;
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
 */
enum anyrtc_code anyrtc_dtls_parameters_create(
        struct anyrtc_dtls_parameters** const parametersp, // de-referenced
        enum anyrtc_dtls_role const role,
        struct anyrtc_dtls_fingerprint* const fingerprints[], // referenced (each item)
        size_t const n_fingerprints
) {
    struct anyrtc_dtls_parameters* parameters;
    size_t i;
    enum anyrtc_code error;

    // Check arguments
    if (!parametersp || !fingerprints || n_fingerprints < 1) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Create parameters
    error = anyrtc_dtls_parameters_allocate(&parameters, role, n_fingerprints);
    if (error) {
        goto out;
    }

    // Reference and set each fingerprint
    for (i = 0; i < n_fingerprints; ++i) {
        // Null?
        if (fingerprints[i] == NULL) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Check algorithm
        if (fingerprints[i]->algorithm == ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
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
enum anyrtc_code anyrtc_dtls_parameters_create_internal(
        struct anyrtc_dtls_parameters** const parametersp, // de-referenced
        enum anyrtc_dtls_role const role,
        struct list* const fingerprints
) {
    size_t n_fingerprints;
    struct anyrtc_dtls_parameters* parameters;
    enum anyrtc_code error;
    struct le* le;
    size_t i;

    // Check arguments
    if (!parametersp || !fingerprints) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Get fingerprints length
    n_fingerprints = list_count(fingerprints);

    // Create parameters
    error = anyrtc_dtls_parameters_allocate(&parameters, role, n_fingerprints);
    if (error) {
        goto out;
    }

    // Reference and set each fingerprint
    for (le = list_head(fingerprints), i = 0; le != NULL; le = le->next, ++i) {
        struct anyrtc_dtls_fingerprint* const fingerprint = le->data;

        // Check algorithm
        if (fingerprint->algorithm == ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
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

/*
 * Get the DTLS parameter's fingerprint array.
 * `*fingerprintsp` must be unreferenced.
 */
enum anyrtc_code anyrtc_dtls_parameters_get_fingerprints(
        struct anyrtc_dtls_fingerprints** const fingerprintsp, // de-referenced
        struct anyrtc_dtls_parameters* const parameters
) {
    // Check arguments
    if (!fingerprintsp || !parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *fingerprintsp = mem_ref(parameters->fingerprints);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum anyrtc_code anyrtc_dtls_parameters_fingerprint_get_sign_algorithm(
        enum anyrtc_certificate_sign_algorithm* const sign_algorithmp, // de-referenced
        struct anyrtc_dtls_fingerprint* const fingerprint
) {
    // Check arguments
    if (!sign_algorithmp || !fingerprint) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set sign algorithm
    *sign_algorithmp = fingerprint->algorithm;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the DTLS certificate's fingerprint value.
 * `*valuep` must be unreferenced.
 */
enum anyrtc_code anyrtc_dtls_parameters_fingerprint_get_value(
        char** const valuep, // de-referenced
        struct anyrtc_dtls_fingerprint* const fingerprint
) {
    // Check arguments
    if (!valuep || !fingerprint) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *valuep = mem_ref(fingerprint->value);
    return ANYRTC_CODE_SUCCESS;
}
