#pragma once
#include <rawrtc/certificate.h>
#include <rawrtcc/code.h>
#include <re.h>

struct rawrtc_dtls_fingerprint {
    struct le le;
    enum rawrtc_certificate_sign_algorithm algorithm;
    char* value; // copied
};

enum rawrtc_code rawrtc_dtls_fingerprint_create_empty(
    struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced
    enum rawrtc_certificate_sign_algorithm const algorithm
);
