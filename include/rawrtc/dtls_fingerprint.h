#pragma once
#include "certificate.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * DTLS fingerprint.
 */
struct rawrtc_dtls_fingerprint;

/*
 * DTLS fingerprints.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_dtls_fingerprints {
    size_t n_fingerprints;
    struct rawrtc_dtls_fingerprint* fingerprints[];
};

/*
 * Create a new DTLS fingerprint instance.
 * `*fingerprintp` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_create(
    struct rawrtc_dtls_fingerprint** const fingerprintp,  // de-referenced
    enum rawrtc_certificate_sign_algorithm const algorithm,
    char* const value  // copied
);

/*
 * Get the DTLS certificate fingerprint's sign algorithm.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_get_sign_algorithm(
    enum rawrtc_certificate_sign_algorithm* const sign_algorithmp,  // de-referenced
    struct rawrtc_dtls_fingerprint* const fingerprint);

/*
 * Get the DTLS certificate's fingerprint value.
 * `*valuep` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_fingerprint_get_value(
    char** const valuep,  // de-referenced
    struct rawrtc_dtls_fingerprint* const fingerprint);
