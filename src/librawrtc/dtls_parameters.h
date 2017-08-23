#pragma once
#include <rawrtc.h>

enum rawrtc_code rawrtc_dtls_fingerprint_create_empty(
    struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum rawrtc_certificate_sign_algorithm const algorithm
);

enum rawrtc_code rawrtc_dtls_parameters_create_internal(
    struct rawrtc_dtls_parameters** const parametersp, // de-referenced
    enum rawrtc_dtls_role const role,
    struct list* const fingerprints
);
