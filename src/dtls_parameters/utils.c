#include "parameters.h"
#include "../dtls_fingerprint/fingerprint.h"
#include <rawrtc/certificate.h>
#include <rawrtc/dtls_fingerprint.h>
#include <rawrtc/dtls_transport.h>
#include <re.h>

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
