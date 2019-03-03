#include "parameters.h"
#include <rawrtc/dtls_fingerprint.h>
#include <rawrtc/dtls_parameters.h>
#include <rawrtc/dtls_transport.h>
#include <rawrtcc/code.h>
#include <re.h>

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
