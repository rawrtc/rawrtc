#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <stdarg.h>
#include <openssl/evp.h> // EVP_MD, evp_*
#include <anyrtc.h>
#include "utils.h"

/*
 * Default anyrtc options.
 */
struct anyrtc_config anyrtc_default_config = {
        .pacing_interval = 20,
        .ipv4_enable = true,
        .ipv6_enable = false, // TODO: true by default
        .udp_enable = true,
        .tcp_enable = false, // TODO: true by default
        .sign_algorithm = ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
};

/*
 * Default certificate options.
 */
struct anyrtc_certificate_options anyrtc_default_certificate_options = {
        .key_type = ANYRTC_CERTIFICATE_KEY_TYPE_EC,
        .common_name = "anonymous@anyrtc.org",
        .valid_until = 3600 * 24 * 30, // 30 days
        .sign_algorithm = ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
        .named_curve = "prime256v1",
        .modulus_length = 2048
};

/*
 * Translate an re error to an anyrtc code.
 * TODO: Add codes from trice_lcand_add
 */
enum anyrtc_code anyrtc_translate_re_code(
        int const code
) {
    switch (code) {
        case 0:
            return ANYRTC_CODE_SUCCESS;
        case EINVAL:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        case ENOMEM:
            return ANYRTC_CODE_NO_MEMORY;
        case EAUTH:
            return ANYRTC_CODE_INVALID_CERTIFICATE;
        default:
            return ANYRTC_CODE_UNKNOWN_ERROR;
    }
}

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int anyrtc_translate_ice_protocol(
        enum anyrtc_ice_protocol const protocol
) {
    // No conversion needed
    return (int) protocol;
}

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum anyrtc_code anyrtc_translate_ipproto(
        int const ipproto,
        enum anyrtc_ice_protocol* const protocolp // de-referenced
) {
    // Check arguments
    if (!protocolp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert IPPROTO_*
    switch (ipproto) {
        case IPPROTO_UDP:
            *protocolp = ANYRTC_ICE_PROTOCOL_UDP;
            return ANYRTC_CODE_SUCCESS;
        case IPPROTO_TCP:
            *protocolp = ANYRTC_ICE_PROTOCOL_TCP;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate an ICE candidate type to the corresponding libre type.
 */
enum ice_cand_type anyrtc_translate_ice_candidate_type(
        enum anyrtc_ice_candidate_type const type
) {
    // No conversion needed
    return (enum ice_cand_type) type;
}

/*
 * Translate a libre ICE candidate type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_translate_re_ice_cand_type(
        enum anyrtc_ice_candidate_type* const typep, // de-referenced
        enum ice_cand_type const re_type
) {
    // Check arguments
    if (!typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case ICE_CAND_TYPE_HOST:
            *typep = ANYRTC_ICE_CANDIDATE_TYPE_HOST;
            return ANYRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_SRFLX:
            *typep = ANYRTC_ICE_CANDIDATE_TYPE_SRFLX;
            return ANYRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_PRFLX:
            *typep = ANYRTC_ICE_CANDIDATE_TYPE_PRFLX;
            return ANYRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_RELAY:
            *typep = ANYRTC_ICE_CANDIDATE_TYPE_RELAY;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate an ICE TCP candidate type to the corresponding libre type.
 */
enum ice_tcptype anyrtc_translate_ice_tcp_candidate_type(
        enum anyrtc_ice_tcp_candidate_type const type
) {
    // No conversion needed
    return (enum ice_tcptype) type;
}

/*
 * Translate a libre ICE TCP candidate type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_translate_re_ice_tcptype(
        enum anyrtc_ice_tcp_candidate_type* const typep, // de-referenced
        enum ice_tcptype const re_type
) {
    // Check arguments
    if (!typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case ICE_TCP_ACTIVE:
            *typep = ANYRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
            return ANYRTC_CODE_SUCCESS;
        case ICE_TCP_PASSIVE:
            *typep = ANYRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE;
            return ANYRTC_CODE_SUCCESS;
        case ICE_TCP_SO:
            *typep = ANYRTC_ICE_TCP_CANDIDATE_TYPE_SO;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate an ICE role to the corresponding libre type.
 */
enum trice_role anyrtc_translate_ice_role(
        enum anyrtc_ice_role const role
) {
    // No conversion needed
    return (enum trice_role) role;
}

/*
 * Translate a libre ICE role to the corresponding anyrtc role.
 */
enum anyrtc_code anyrtc_translate_re_trice_role(
        enum anyrtc_ice_role* const rolep, // de-referenced
        enum trice_role const re_role
) {
    // Check arguments
    if (!rolep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Translate role
    switch (re_role) {
        case ROLE_CONTROLLING:
            *rolep = ANYRTC_ICE_ROLE_CONTROLLING;
            return ANYRTC_CODE_SUCCESS;
        case ROLE_CONTROLLED:
            *rolep = ANYRTC_ICE_ROLE_CONTROLLED;
            return ANYRTC_CODE_SUCCESS;
        case ROLE_UNKNOWN:
            *rolep = ANYRTC_ICE_ROLE_UNKNOWN;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate a certificate key type to the corresponding libre type.
 */
enum tls_key_type anyrtc_translate_certificate_key_type(
        enum anyrtc_certificate_key_type const type
) {
    // No conversion needed
    return (enum tls_key_type) type;
}

/*
 * Translate a libre key type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_translate_re_tls_key_type(
        enum anyrtc_certificate_key_type* const typep, // de-referenced
        enum tls_key_type const re_type
) {
    // Check arguments
    if (!typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case TLS_KEY_TYPE_RSA:
            *typep = ANYRTC_CERTIFICATE_KEY_TYPE_RSA;
            return ANYRTC_CODE_SUCCESS;
        case TLS_KEY_TYPE_EC:
            *typep = ANYRTC_CERTIFICATE_KEY_TYPE_EC;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate a certificate sign algorithm to the corresponding libre fingerprint algorithm.
 */
enum anyrtc_code anyrtc_translate_certificate_sign_algorithm(
        enum tls_fingerprint* const fingerprintp, // de-referenced
        enum anyrtc_certificate_sign_algorithm const algorithm
) {
    switch (algorithm) {
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to libre)
            return ANYRTC_CODE_UNSUPPORTED_ALGORITHM;
        default:
            break;
    }

    // No conversion needed
    *fingerprintp = (enum tls_fingerprint) algorithm;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Translate a libre fingerprint algorithm to the corresponding anyrtc algorithm.
 */
enum anyrtc_code anyrtc_translate_re_tls_fingerprint(
        enum anyrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        enum tls_fingerprint re_algorithm
) {
    // Check arguments
    if (!algorithmp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to libre)
    switch (re_algorithm) {
        case TLS_FINGERPRINT_SHA1:
            *algorithmp = ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA1;
            return ANYRTC_CODE_SUCCESS;
        case TLS_FINGERPRINT_SHA256:
            *algorithmp = ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Get the EVP_MD* structure for a certificate sign algorithm type.
 */
EVP_MD const * const anyrtc_get_sign_function(
        enum anyrtc_certificate_sign_algorithm const type
) {
    switch (type) {
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA1:
            return EVP_sha1();
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256:
            return EVP_sha256();
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
            return EVP_sha384();
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            return EVP_sha512();
        default:
            return NULL;
    }
}

/*
 * Get the length of the fingerprint to a certificate sign algorithm type.
 */
enum anyrtc_code anyrtc_get_sign_algorithm_length(
        size_t* const sizep, // de-referenced
        enum anyrtc_certificate_sign_algorithm const type
) {
    EVP_MD const * sign_function;
    int size;

    // Get sign algorithm function
    sign_function = anyrtc_get_sign_function(type);
    if (!sign_function) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Get length
    size = EVP_MD_size(sign_function);
    if (size < 1) {
        return ANYRTC_CODE_UNSUPPORTED_ALGORITHM;
    }

    // Set size
    *sizep = (size_t) size;
    return ANYRTC_CODE_SUCCESS;
}

enum anyrtc_code anyrtc_strdup(
        char** const destination,
        char const * const source
) {
    int err = str_dup(destination, source);
    return anyrtc_translate_re_code(err);
}

enum anyrtc_code anyrtc_snprintf(
        char* const destination,
        size_t const size,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsnprintf(destination, size, formatter, args);
    va_end(args);

    // For some reason, re_vsnprintf does return -1 on argument error
    switch (err) {
        case -1:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        default:
            return anyrtc_translate_re_code(err);
    }
}

enum anyrtc_code anyrtc_sdprintf(
        char** const destinationp,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsdprintf(destinationp, formatter, args);
    va_end(args);
    return anyrtc_translate_re_code(err);
}

