#include "certificate.h"
#include <rawrtc/certificate.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Translate a certificate key type to the corresponding re type.
 */
enum tls_keytype rawrtc_certificate_key_type_to_tls_keytype(
        enum rawrtc_certificate_key_type const type
) {
    // No conversion needed
    return (enum tls_keytype) type;
}

/*
 * Translate a re key type to the corresponding rawrtc type.
 */
enum rawrtc_code rawrtc_tls_keytype_to_certificate_key_type(
        enum rawrtc_certificate_key_type* const typep, // de-referenced
        enum tls_keytype const re_type
) {
    // Check arguments
    if (!typep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case TLS_KEYTYPE_RSA:
            *typep = RAWRTC_CERTIFICATE_KEY_TYPE_RSA;
            return RAWRTC_CODE_SUCCESS;
        case TLS_KEYTYPE_EC:
            *typep = RAWRTC_CERTIFICATE_KEY_TYPE_EC;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate a certificate sign algorithm to the corresponding re fingerprint algorithm.
 */
enum rawrtc_code rawrtc_certificate_sign_algorithm_to_tls_fingerprint(
        enum tls_fingerprint* const fingerprintp, // de-referenced
        enum rawrtc_certificate_sign_algorithm const algorithm
) {
    switch (algorithm) {
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_NONE:
            return RAWRTC_CODE_INVALID_ARGUMENT;
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to re)
            return RAWRTC_CODE_UNSUPPORTED_ALGORITHM;
        default:
            break;
    }

    // No conversion needed
    *fingerprintp = (enum tls_fingerprint) algorithm;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Translate a re fingerprint algorithm to the corresponding rawrtc algorithm.
 */
enum rawrtc_code rawrtc_tls_fingerprint_to_certificate_sign_algorithm(
        enum rawrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        enum tls_fingerprint re_algorithm
) {
    // Check arguments
    if (!algorithmp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to libre)
    switch (re_algorithm) {
        case TLS_FINGERPRINT_SHA256:
            *algorithmp = RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static enum rawrtc_certificate_sign_algorithm const map_enum_certificate_sign_algorithm[] = {
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384,
    RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512,
};

static char const * const map_str_certificate_sign_algorithm[] = {
    "sha-256",
    "sha-384",
    "sha-512",
};

static size_t const map_certificate_sign_algorithm_length =
    ARRAY_SIZE(map_enum_certificate_sign_algorithm);

/*
 * Translate a certificate sign algorithm to str.
 */
char const * rawrtc_certificate_sign_algorithm_to_str(
        enum rawrtc_certificate_sign_algorithm const algorithm
) {
    size_t i;

    for (i = 0; i < map_certificate_sign_algorithm_length; ++i) {
        if (map_enum_certificate_sign_algorithm[i] == algorithm) {
            return map_str_certificate_sign_algorithm[i];
        }
    }

    return "???";
}

/*
 * Translate a str to a certificate sign algorithm (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_certificate_sign_algorithm(
        enum rawrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!algorithmp || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_certificate_sign_algorithm_length; ++i) {
        if (str_casecmp(map_str_certificate_sign_algorithm[i], str) == 0) {
            *algorithmp = map_enum_certificate_sign_algorithm[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Get the EVP_MD* structure for a certificate sign algorithm type.
 */
EVP_MD const * rawrtc_get_sign_function(
        enum rawrtc_certificate_sign_algorithm const type
) {
    switch (type) {
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256:
            return EVP_sha256();
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
            return EVP_sha384();
        case RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

/*
 * Get the length of the fingerprint to a certificate sign algorithm type.
 */
enum rawrtc_code rawrtc_get_sign_algorithm_length(
        size_t* const sizep, // de-referenced
        enum rawrtc_certificate_sign_algorithm const type
) {
    EVP_MD const * sign_function;
    int size;

    // Get sign algorithm function
    sign_function = rawrtc_get_sign_function(type);
    if (!sign_function) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get length
    size = EVP_MD_size(sign_function);
    if (size < 1) {
        return RAWRTC_CODE_UNSUPPORTED_ALGORITHM;
    }

    // Set size
    *sizep = (size_t) size;
    return RAWRTC_CODE_SUCCESS;
}
