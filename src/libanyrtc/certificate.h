#pragma once

enum anyrtc_code anyrtc_certificate_copy(
    struct anyrtc_certificate** const certificatep, // de-referenced
    struct anyrtc_certificate* const source_certificate
);

enum anyrtc_code anyrtc_certificate_get_pem(
    char** const pemp,  // de-referenced
    size_t* const pem_lengthp,  // de-referenced
    struct anyrtc_certificate* const certificate,
    enum anyrtc_certificate_encode const to_encode
);

enum anyrtc_code anyrtc_certificate_get_der(
    uint8_t** const derp,  // de-referenced
    size_t* const der_lengthp,  // de-referenced
    struct anyrtc_certificate* const certificate,
    enum anyrtc_certificate_encode const to_encode
);
