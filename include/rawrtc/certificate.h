#pragma once
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Certificate private key types.
 */
enum rawrtc_certificate_key_type {
    // An RSA private key.
    RAWRTC_CERTIFICATE_KEY_TYPE_RSA = TLS_KEYTYPE_RSA,
    // An elliptic curve private key.
    RAWRTC_CERTIFICATE_KEY_TYPE_EC = TLS_KEYTYPE_EC,
};

/*
 * Certificate signing hash algorithms.
 */
enum rawrtc_certificate_sign_algorithm {
    // Sign algorithm not set.
    // Note: When passing this as an argument, a sensible default signing
    //       algorithm shall be used.
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE = 0,
    // SHA-256 sign algorithm.
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256 = TLS_FINGERPRINT_SHA256,
    // SHA-384 sign algorithm.
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384,
    // SHA-512 sign algorithm.
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512,
};

/*
 * Certificate encoding.
 */
enum rawrtc_certificate_encode {
    // Only encode the certificate.
    RAWRTC_CERTIFICATE_ENCODE_CERTIFICATE,
    // Only encode the private key.
    RAWRTC_CERTIFICATE_ENCODE_PRIVATE_KEY,
    // Encode both the certificate and the private key.
    RAWRTC_CERTIFICATE_ENCODE_BOTH,
};

/*
 * Certificate options.
 */
struct rawrtc_certificate_options;

/*
 * Certificate.
 */
struct rawrtc_certificate;

/*
 * Certificates.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_certificates {
    size_t n_certificates;
    struct rawrtc_certificate* certificates[];
};

/*
 * Create certificate options.
 *
 * All arguments but `key_type` are optional. Sane and safe default
 * values will be applied, don't worry!
 *
 * `*optionsp` must be unreferenced.
 *
 * If `common_name` is `NULL` the default common name will be applied.
 * If `valid_until` is `0` the default certificate lifetime will be
 * applied.
 * If the key type is `ECC` and `named_curve` is `NULL`, the default
 * named curve will be used.
 * If the key type is `RSA` and `modulus_length` is `0`, the default
 * amount of bits will be used. The same applies to the
 * `sign_algorithm` if it has been set to `NONE`.
 */
enum rawrtc_code rawrtc_certificate_options_create(
    struct rawrtc_certificate_options** const optionsp, // de-referenced
    enum rawrtc_certificate_key_type const key_type,
    char* common_name, // nullable, copied
    uint_fast32_t valid_until,
    enum rawrtc_certificate_sign_algorithm sign_algorithm,
    char* named_curve, // nullable, copied, ignored for RSA
    uint_fast32_t modulus_length // ignored for ECC
);

/*
 * Create and generate a self-signed certificate.
 *
 * Sane and safe default options will be applied if `options` is
 * `NULL`.
 *
 * `*certificatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_certificate_generate(
    struct rawrtc_certificate** const certificatep,
    struct rawrtc_certificate_options* options // nullable
);

/*
 * TODO http://draft.ortc.org/#dom-rtccertificate
 * rawrtc_certificate_from_bytes
 * rawrtc_certificate_get_expires
 * rawrtc_certificate_get_fingerprint
 * rawrtc_certificate_get_algorithm
 */

/*
 * Translate a certificate sign algorithm to str.
 */
char const * rawrtc_certificate_sign_algorithm_to_str(
    enum rawrtc_certificate_sign_algorithm const algorithm
);

/*
 * Translate a str to a certificate sign algorithm (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_certificate_sign_algorithm(
    enum rawrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
    char const * const str
);
