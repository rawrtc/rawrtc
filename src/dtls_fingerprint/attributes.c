#include "fingerprint.h"
#include <rawrtc/certificate.h>
#include <rawrtc/dtls_fingerprint.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_get_sign_algorithm(
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
enum rawrtc_code rawrtc_dtls_fingerprint_get_value(
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
