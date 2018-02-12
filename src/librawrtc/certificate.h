#pragma once
#include <openssl/evp.h> // EVP_MAX_MD_SIZE

/*
 * Maximum digest size of certificate fingerprint.
 */
enum {
    RAWRTC_FINGERPRINT_MAX_SIZE = EVP_MAX_MD_SIZE,
    RAWRTC_FINGERPRINT_MAX_SIZE_HEX = (EVP_MAX_MD_SIZE * 2)
};

enum rawrtc_code rawrtc_certificate_copy(
    struct rawrtc_certificate** const certificatep, // de-referenced
    struct rawrtc_certificate* const source_certificate
);

enum rawrtc_code rawrtc_certificate_get_pem(
    char** const pemp,  // de-referenced
    size_t* const pem_lengthp,  // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_encode const to_encode
);

enum rawrtc_code rawrtc_certificate_get_der(
    uint8_t** const derp,  // de-referenced
    size_t* const der_lengthp,  // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_encode const to_encode
);

enum rawrtc_code rawrtc_certificate_get_fingerprint(
    char** const fingerprint, // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_sign_algorithm const algorithm
);

enum rawrtc_code rawrtc_certificate_array_to_list(
    struct list* const certificate_list, // de-referenced, copied into
    struct rawrtc_certificate* const certificates[], // copied (each item)
    size_t const n_certificates
);

enum rawrtc_code rawrtc_certificate_list_copy(
    struct list* const destination_list, // de-referenced, copied into
    struct list* const source_list // de-referenced, copied (each item)
);
