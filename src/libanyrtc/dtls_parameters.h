#pragma once

enum anyrtc_code anyrtc_dtls_fingerprint_create_empty(
    struct anyrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum anyrtc_certificate_sign_algorithm const algorithm
);

enum anyrtc_code anyrtc_dtls_parameters_create_internal(
    struct anyrtc_dtls_parameters** const parametersp, // de-referenced
    enum anyrtc_dtls_role const role,
    struct list* const fingerprints
);
