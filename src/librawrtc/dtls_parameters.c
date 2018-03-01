#include <rawrtc.h>
#include "dtls_parameters.h"

/*
 * Destructor for an existing DTLS fingerprint instance.
 */
static void rawrtc_dtls_fingerprint_destroy(
        void* arg
) {
    struct rawrtc_dtls_fingerprint* const fingerprint = arg;

    // Un-reference
    mem_deref(fingerprint->value);
}

/*
 * Create a new DTLS fingerprint instance.
 * `*fingerprintp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_create(
        struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced
        enum rawrtc_certificate_sign_algorithm const algorithm,
        char* const value // copied
) {
    struct rawrtc_dtls_fingerprint* fingerprint;
    enum rawrtc_code error;

    // Allocate
    fingerprint = mem_zalloc(sizeof(*fingerprint), rawrtc_dtls_fingerprint_destroy);
    if (!fingerprint) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    fingerprint->algorithm = algorithm;
    error = rawrtc_strdup(&fingerprint->value, value);
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
enum rawrtc_code rawrtc_dtls_fingerprint_create_empty(
        struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced
        enum rawrtc_certificate_sign_algorithm const algorithm
) {
    struct rawrtc_dtls_fingerprint* fingerprint;

    // Allocate
    fingerprint = mem_zalloc(sizeof(*fingerprint), rawrtc_dtls_fingerprint_destroy);
    if (!fingerprint) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    fingerprint->algorithm = algorithm;

    // Set pointer
    *fingerprintp = fingerprint;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing DTLS parameter's fingerprints instance.
 */
static void rawrtc_dtls_parameters_fingerprints_destroy(
        void* arg
) {
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
static void rawrtc_dtls_parameters_destroy(
        void* arg
) {
    struct rawrtc_dtls_parameters* const parameters = arg;

    // Un-reference
    mem_deref(parameters->fingerprints);
}

/*
 * Common code to allocate a DTLS parameters instance.
 */
static enum rawrtc_code rawrtc_dtls_parameters_allocate(
        struct rawrtc_dtls_parameters** const parametersp, // de-referenced
        enum rawrtc_dtls_role const role,
        size_t const n_fingerprints
) {
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
    parameters->fingerprints = mem_zalloc(sizeof(*parameters) + fingerprints_size,
                                          rawrtc_dtls_parameters_fingerprints_destroy);
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
        struct rawrtc_dtls_parameters** const parametersp, // de-referenced
        enum rawrtc_dtls_role const role,
        struct rawrtc_dtls_fingerprint* const fingerprints[], // referenced (each item)
        size_t const n_fingerprints
) {
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
        struct rawrtc_dtls_parameters** const parametersp, // de-referenced
        enum rawrtc_dtls_role const role,
        struct list* const fingerprints
) {
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

/*
 * Print debug information for DTLS parameters.
 */
int rawrtc_dtls_parameters_debug(
        struct re_printf* const pf,
        struct rawrtc_dtls_parameters const* const parameters
) {
    int err = 0;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;

    // Check arguments
    if (!parameters) {
        return 0;
    }

    err |= re_hprintf(pf, "  DTLS Parameters <%p>:\n", parameters);

    // Role
    err |= re_hprintf(pf, "    role=%s\n", rawrtc_dtls_role_to_str(parameters->role));

    // Fingerprints
    fingerprints = parameters->fingerprints;
    err |= re_hprintf(pf, "    Fingerprints <%p>:\n", fingerprints);
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        // Fingerprint
        err |= re_hprintf(
                pf, "      algorithm=%s value=%s\n",
                rawrtc_certificate_sign_algorithm_to_str(fingerprints->fingerprints[i]->algorithm),
                fingerprints->fingerprints[i]->value);
    }

    // Done
    return err;
}

/*
 * Get the DTLS parameter's role value.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_role(
        enum rawrtc_dtls_role* rolep, // de-referenced
        struct rawrtc_dtls_parameters* const parameters
) {
    // Check arguments
    if (!rolep || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *rolep = parameters->role;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the DTLS parameter's fingerprint array.
 * `*fingerprintsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_fingerprints(
        struct rawrtc_dtls_fingerprints** const fingerprintsp, // de-referenced
        struct rawrtc_dtls_parameters* const parameters
) {
    // Check arguments
    if (!fingerprintsp || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer (and reference)
    *fingerprintsp = mem_ref(parameters->fingerprints);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum rawrtc_code rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(
        enum rawrtc_certificate_sign_algorithm* const sign_algorithmp, // de-referenced
        struct rawrtc_dtls_fingerprint* const fingerprint
) {
    // Check arguments
    if (!sign_algorithmp || !fingerprint) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set sign algorithm
    *sign_algorithmp = fingerprint->algorithm;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the DTLS certificate's fingerprint value.
 * `*valuep` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_fingerprint_get_value(
        char** const valuep, // de-referenced
        struct rawrtc_dtls_fingerprint* const fingerprint
) {
    // Check arguments
    if (!valuep || !fingerprint) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *valuep = mem_ref(fingerprint->value);
    return RAWRTC_CODE_SUCCESS;
}
