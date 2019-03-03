#include "fingerprint.h"
#include <rawrtc/certificate.h>
#include <rawrtc/dtls_fingerprint.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

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
