#pragma once
#include <rawrtc/certificate.h>
#include <re.h>
#include <openssl/evp.h>  // EVP_*
#include <openssl/x509.h>  // X509

/*
 * Maximum digest size of certificate fingerprint.
 */
enum {
    RAWRTC_MODULUS_LENGTH_MIN = 1024,
    RAWRTC_FINGERPRINT_MAX_SIZE = EVP_MAX_MD_SIZE,
    RAWRTC_FINGERPRINT_MAX_SIZE_HEX = (EVP_MAX_MD_SIZE * 2),
};

/*
 * Certificate options.
 */
struct rawrtc_certificate_options {
    enum rawrtc_certificate_key_type key_type;
    char* common_name;  // copied
    uint_fast32_t valid_until;
    enum rawrtc_certificate_sign_algorithm sign_algorithm;
    char* named_curve;  // nullable, copied, ignored for RSA
    uint_fast32_t modulus_length;  // ignored for ECC
};

/*
 * Certificate.
 */
struct rawrtc_certificate {
    struct le le;
    X509* certificate;
    EVP_PKEY* key;
    enum rawrtc_certificate_key_type key_type;
};

extern struct rawrtc_certificate_options rawrtc_default_certificate_options;

enum rawrtc_code rawrtc_certificate_copy(
    struct rawrtc_certificate** const certificatep,  // de-referenced
    struct rawrtc_certificate* const source_certificate);

enum rawrtc_code rawrtc_certificate_get_pem(
    char** const pemp,  // de-referenced
    size_t* const pem_lengthp,  // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_encode const to_encode);

enum rawrtc_code rawrtc_certificate_get_der(
    uint8_t** const derp,  // de-referenced
    size_t* const der_lengthp,  // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_encode const to_encode);

enum rawrtc_code rawrtc_certificate_get_fingerprint(
    char** const fingerprint,  // de-referenced
    struct rawrtc_certificate* const certificate,
    enum rawrtc_certificate_sign_algorithm const algorithm);

enum rawrtc_code rawrtc_certificate_array_to_list(
    struct list* const certificate_list,  // de-referenced, copied into
    struct rawrtc_certificate* const certificates[],  // copied (each item)
    size_t const n_certificates);

enum rawrtc_code rawrtc_certificate_list_copy(
    struct list* const destination_list,  // de-referenced, copied into
    struct list* const source_list  // de-referenced, copied (each item)
);

enum tls_keytype rawrtc_certificate_key_type_to_tls_keytype(
    const enum rawrtc_certificate_key_type type);

enum rawrtc_code rawrtc_tls_keytype_to_certificate_key_type(
    enum rawrtc_certificate_key_type* const typep,  // de-referenced
    enum tls_keytype const re_type);

enum rawrtc_code rawrtc_certificate_sign_algorithm_to_tls_fingerprint(
    enum tls_fingerprint* const fingerprintp,  // de-referenced
    enum rawrtc_certificate_sign_algorithm const algorithm);

enum rawrtc_code rawrtc_tls_fingerprint_to_certificate_sign_algorithm(
    enum rawrtc_certificate_sign_algorithm* const algorithmp,  // de-referenced
    enum tls_fingerprint re_algorithm);

EVP_MD const* rawrtc_get_sign_function(enum rawrtc_certificate_sign_algorithm type);

enum rawrtc_code rawrtc_get_sign_algorithm_length(
    size_t* const sizep,  // de-referenced
    enum rawrtc_certificate_sign_algorithm const type);
