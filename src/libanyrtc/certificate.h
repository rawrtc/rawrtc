#pragma once

enum anyrtc_code anyrtc_certificate_copy(
    struct anyrtc_certificate** const certificatep, // de-referenced
    struct anyrtc_certificate* const source_certificate
);
