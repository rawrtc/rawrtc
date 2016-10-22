#pragma once

enum anyrtc_code anyrtc_dtls_fingerprint_create_empty(
    struct anyrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum anyrtc_certificate_sign_algorithm const algorithm
);

enum anyrtc_code anyrtc_dtls_parameters_create_local(
    struct anyrtc_dtls_parameters** const parametersp, // de-referenced, not checked
    struct anyrtc_dtls_transport* const transport // not checked
);
