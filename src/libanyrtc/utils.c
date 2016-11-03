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
 * Translate an anyrtc return code to a string.
 */
char const* anyrtc_code_to_str(
        enum anyrtc_code const code
) {
    switch (code) {
        case ANYRTC_CODE_UNKNOWN_ERROR:
            return "unknown error";
        case ANYRTC_CODE_NOT_IMPLEMENTED:
            return "not implemented";
        case ANYRTC_CODE_SUCCESS:
            return "success";
        case ANYRTC_CODE_INITIALISE_FAIL:
            return "failed to initialise";
        case ANYRTC_CODE_INVALID_ARGUMENT:
            return "invalid argument";
        case ANYRTC_CODE_NO_MEMORY:
            return "no memory";
        case ANYRTC_CODE_INVALID_STATE:
            return "invalid state";
        case ANYRTC_CODE_UNSUPPORTED_PROTOCOL:
            return "unsupported protocol";
        case ANYRTC_CODE_UNSUPPORTED_ALGORITHM:
            return "unsupported algorithm";
        case ANYRTC_CODE_NO_VALUE:
            return "no value";
        case ANYRTC_CODE_NO_SOCKET:
            return "no socket";
        case ANYRTC_CODE_INVALID_CERTIFICATE:
            return "invalid certificate";
        case ANYRTC_CODE_INVALID_FINGERPRINT:
            return "invalid fingerprint";
        default:
            return "(no error translation)";
    }
}

/*
 * Translate an re error to an anyrtc code.
 * TODO: Add codes from trice_lcand_add
 */
enum anyrtc_code anyrtc_error_to_code(
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
int anyrtc_ice_protocol_to_ipproto(
        enum anyrtc_ice_protocol const protocol
) {
    // No conversion needed
    return (int) protocol;
}

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum anyrtc_code anyrtc_ipproto_to_ice_protocol(
        enum anyrtc_ice_protocol* const protocolp, // de-referenced
        int const ipproto
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

enum anyrtc_ice_protocol const map_enum_ice_protocol[] = {
    ANYRTC_ICE_PROTOCOL_UDP,
    ANYRTC_ICE_PROTOCOL_TCP,
};

char const * const map_str_ice_protocol[] = {
    "udp",
    "tcp",
};

size_t const map_ice_protocol_length =
        sizeof(map_enum_ice_protocol) / sizeof(map_enum_ice_protocol[0]);

/*
 * Translate an ICE protocol to str.
 */
char const * anyrtc_ice_protocol_to_str(
        enum anyrtc_ice_protocol const protocol
) {
    size_t i;

    for (i = 0; i < map_ice_protocol_length; ++i) {
        if (map_enum_ice_protocol[i] == protocol) {
            return map_str_ice_protocol[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE protocol (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_protocol(
        enum anyrtc_ice_protocol* const protocolp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!protocolp || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_protocol_length; ++i) {
        if (str_casecmp(map_str_ice_protocol[i], str) == 0) {
            *protocolp = map_enum_ice_protocol[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE candidate type to the corresponding re type.
 */
enum ice_cand_type anyrtc_ice_candidate_type_to_ice_cand_type(
        enum anyrtc_ice_candidate_type const type
) {
    // No conversion needed
    return (enum ice_cand_type) type;
}

/*
 * Translate a re ICE candidate type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_ice_cand_type_to_ice_candidate_type(
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

enum anyrtc_ice_candidate_type const map_enum_ice_candidate_type[] = {
    ANYRTC_ICE_CANDIDATE_TYPE_HOST,
    ANYRTC_ICE_CANDIDATE_TYPE_SRFLX,
    ANYRTC_ICE_CANDIDATE_TYPE_PRFLX,
    ANYRTC_ICE_CANDIDATE_TYPE_RELAY,
};

char const * const map_str_ice_candidate_type[] = {
    "host",
    "srflx",
    "prflx",
    "relay",
};

size_t const map_ice_candidate_type_length =
        sizeof(map_enum_ice_candidate_type) / sizeof(map_enum_ice_candidate_type[0]);

/*
 * Translate an ICE candidate type to str.
 */
char const * anyrtc_ice_candidate_type_to_str(
        enum anyrtc_ice_candidate_type const type
) {
    size_t i;

    for (i = 0; i < map_ice_candidate_type_length; ++i) {
        if (map_enum_ice_candidate_type[i] == type) {
            return map_str_ice_candidate_type[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE candidate type (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_candidate_type(
        enum anyrtc_ice_candidate_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_candidate_type_length; ++i) {
        if (str_casecmp(map_str_ice_candidate_type[i], str) == 0) {
            *typep = map_enum_ice_candidate_type[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE TCP candidate type to the corresponding re type.
 */
enum ice_tcptype anyrtc_ice_tcp_candidate_type_to_ice_tcptype(
        enum anyrtc_ice_tcp_candidate_type const type
) {
    // No conversion needed
    return (enum ice_tcptype) type;
}

/*
 * Translate a re ICE TCP candidate type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_ice_tcptype_to_ice_tcp_candidate_type(
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

enum anyrtc_ice_tcp_candidate_type const map_enum_ice_tcp_candidate_type[] = {
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE,
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE,
    ANYRTC_ICE_TCP_CANDIDATE_TYPE_SO,
};

char const * const map_str_ice_tcp_candidate_type[] = {
    "active",
    "passive",
    "so",
};

size_t const map_ice_tcp_candidate_type_length =
        sizeof(map_enum_ice_tcp_candidate_type) / sizeof(map_enum_ice_tcp_candidate_type[0]);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const * anyrtc_ice_tcp_candidate_type_to_str(
        enum anyrtc_ice_tcp_candidate_type const type
) {
    size_t i;

    for (i = 0; i < map_ice_tcp_candidate_type_length; ++i) {
        if (map_enum_ice_tcp_candidate_type[i] == type) {
            return map_str_ice_tcp_candidate_type[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_tcp_candidate_type(
        enum anyrtc_ice_tcp_candidate_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_tcp_candidate_type_length; ++i) {
        if (str_casecmp(map_str_ice_tcp_candidate_type[i], str) == 0) {
            *typep = map_enum_ice_tcp_candidate_type[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE role to the corresponding re type.
 */
enum trice_role anyrtc_ice_role_to_trice_role(
        enum anyrtc_ice_role const role
) {
    // No conversion needed
    return (enum trice_role) role;
}

/*
 * Translate a re ICE role to the corresponding anyrtc role.
 */
enum anyrtc_code anyrtc_trice_role_to_ice_role(
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

enum anyrtc_ice_role const map_enum_ice_role[] = {
    ANYRTC_ICE_ROLE_CONTROLLING,
    ANYRTC_ICE_ROLE_CONTROLLED,
};

char const * const map_str_ice_role[] = {
    "controlling",
    "controlled",
};

size_t const map_ice_role_length =
        sizeof(map_enum_ice_role) / sizeof(map_enum_ice_role[0]);

/*
 * Translate an ICE role to str.
 */
char const * anyrtc_ice_role_to_str(
        enum anyrtc_ice_role const role
) {
    size_t i;

    for (i = 0; i < map_ice_role_length; ++i) {
        if (map_enum_ice_role[i] == role) {
            return map_str_ice_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE role (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_ice_role(
        enum anyrtc_ice_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_role_length; ++i) {
        if (str_casecmp(map_str_ice_role[i], str) == 0) {
            *rolep = map_enum_ice_role[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
}

/*
 * Translate a certificate key type to the corresponding re type.
 */
enum tls_keytype anyrtc_certificate_key_type_to_tls_keytype(
        enum anyrtc_certificate_key_type const type
) {
    // No conversion needed
    return (enum tls_keytype) type;
}

enum anyrtc_dtls_role const map_enum_dtls_role[] = {
    ANYRTC_DTLS_ROLE_AUTO,
    ANYRTC_DTLS_ROLE_CLIENT,
    ANYRTC_DTLS_ROLE_SERVER,
};

char const * const map_str_dtls_role[] = {
    "auto",
    "client",
    "server",
};

size_t const map_dtls_role_length =
        sizeof(map_enum_dtls_role) / sizeof(map_enum_dtls_role[0]);

/*
 * Translate a DTLS role to str.
 */
char const * anyrtc_dtls_role_to_str(
        enum anyrtc_dtls_role const role
) {
    size_t i;

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (map_enum_dtls_role[i] == role) {
            return map_str_dtls_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to a DTLS role (case-insensitive).
 */
enum anyrtc_code anyrtc_str_to_dtls_role(
        enum anyrtc_dtls_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (str_casecmp(map_str_dtls_role[i], str) == 0) {
            *rolep = map_enum_dtls_role[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
}

/*
 * Translate a re key type to the corresponding anyrtc type.
 */
enum anyrtc_code anyrtc_tls_keytype_to_certificate_key_type(
        enum anyrtc_certificate_key_type* const typep, // de-referenced
        enum tls_keytype const re_type
) {
    // Check arguments
    if (!typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case TLS_KEYTYPE_RSA:
            *typep = ANYRTC_CERTIFICATE_KEY_TYPE_RSA;
            return ANYRTC_CODE_SUCCESS;
        case TLS_KEYTYPE_EC:
            *typep = ANYRTC_CERTIFICATE_KEY_TYPE_EC;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_ARGUMENT;
    }
}

/*
 * Translate a certificate sign algorithm to the corresponding re fingerprint algorithm.
 */
enum anyrtc_code anyrtc_certificate_sign_algorithm_to_tls_fingerprint(
        enum tls_fingerprint* const fingerprintp, // de-referenced
        enum anyrtc_certificate_sign_algorithm const algorithm
) {
    switch (algorithm) {
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_NONE:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384:
        case ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512:
            // Note: SHA-384 and SHA-512 are currently not supported (needs to be added to re)
            return ANYRTC_CODE_UNSUPPORTED_ALGORITHM;
        default:
            break;
    }

    // No conversion needed
    *fingerprintp = (enum tls_fingerprint) algorithm;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Translate a re fingerprint algorithm to the corresponding anyrtc algorithm.
 */
enum anyrtc_code anyrtc_tls_fingerprint_to_certificate_sign_algorithm(
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

enum anyrtc_certificate_sign_algorithm const map_enum_certificate_sign_algorithm[] = {
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA1,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA384,
    ANYRTC_CERTIFICATE_SIGN_ALGORITHM_SHA512,
};

char const * const map_str_certificate_sign_algorithm[] = {
    "sha-1",
    "sha-256",
    "sha-384",
    "sha-512",
};

size_t const map_certificate_sign_algorithm_length =
        sizeof(map_enum_certificate_sign_algorithm) / sizeof(map_enum_certificate_sign_algorithm[0]);

/*
 * Translate a certificate sign algorithm to str.
 */
char const * anyrtc_certificate_sign_algorithm_to_str(
        enum anyrtc_certificate_sign_algorithm const algorithm
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
enum anyrtc_code anyrtc_str_to_certificate_sign_algorithm(
        enum anyrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!algorithmp || !str) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_certificate_sign_algorithm_length; ++i) {
        if (str_casecmp(map_str_certificate_sign_algorithm[i], str) == 0) {
            *algorithmp = map_enum_certificate_sign_algorithm[i];
            return ANYRTC_CODE_SUCCESS;
        }
    }

    return ANYRTC_CODE_NO_VALUE;
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

/*
 * Duplicate a string.
 */
enum anyrtc_code anyrtc_strdup(
        char** const destination,
        char const * const source
) {
    int err = str_dup(destination, source);
    return anyrtc_error_to_code(err);
}

/*
 * Print a formatted string to a buffer.
 */
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
            return anyrtc_error_to_code(err);
    }
}

/*
 * Print a formatted string to a dynamically allocated buffer.
 */
enum anyrtc_code anyrtc_sdprintf(
        char** const destinationp,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsdprintf(destinationp, formatter, args);
    va_end(args);
    return anyrtc_error_to_code(err);
}

