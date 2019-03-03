#pragma once
#include "dtls_transport.h"
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_dtls_fingerprint;
struct rawrtc_dtls_fingerprints;

/*
 * DTLS parameters.
 */
struct rawrtc_dtls_parameters;

/*
 * Create a new DTLS parameters instance.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_create(
    struct rawrtc_dtls_parameters** const parametersp, // de-referenced
    enum rawrtc_dtls_role const role,
    struct rawrtc_dtls_fingerprint* const fingerprints[], // referenced (each item)
    size_t const n_fingerprints
);

/*
 * Get the DTLS parameter's role value.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_role(
    enum rawrtc_dtls_role* rolep, // de-referenced
    struct rawrtc_dtls_parameters* const parameters
);

/*
 * Get the DTLS parameter's fingerprint array.
 * `*fingerprintsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_parameters_get_fingerprints(
    struct rawrtc_dtls_fingerprints** const fingerprintsp, // de-referenced
    struct rawrtc_dtls_parameters* const parameters
);
