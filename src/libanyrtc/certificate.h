#pragma once
#include <openssl/evp.h> // EVP_MAX_MD_SIZE

/*
 * Maximum digest size of certificate fingerprint.
 */
enum {
    ANYRTC_FINGERPRINT_MAX_SIZE = EVP_MAX_MD_SIZE,
    ANYRTC_FINGERPRINT_MAX_SIZE_HEX = (EVP_MAX_MD_SIZE * 2)
};

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

enum anyrtc_code anyrtc_certificate_get_fingerprint(
    char** const fingerprint, // de-referenced
    struct anyrtc_certificate* const certificate,
    enum anyrtc_certificate_sign_algorithm const algorithm
);
