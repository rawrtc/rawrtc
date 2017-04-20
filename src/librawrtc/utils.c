#include <stdio.h> // sprintf
#include <string.h> // strlen
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <stdarg.h>
#include <openssl/evp.h> // EVP_MD, evp_*
#include <rawrtc.h>
#include "utils.h"

#define DEBUG_MODULE "utils"
// Note: Always log level 7 as logging is only used in tool functions.
#define RAWRTC_DEBUG_MODULE_LEVEL 7
#include "debug.h"

/*
 * Default rawrtc options.
 */
struct rawrtc_config rawrtc_default_config = {
    .pacing_interval = 20,
    .ipv4_enable = true,
    .ipv6_enable = true,
    .udp_enable = true,
    .tcp_enable = false, // TODO: true by default
    .sign_algorithm = RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
    .ice_server_normal_transport = RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    .ice_server_secure_transport = RAWRTC_ICE_SERVER_TRANSPORT_TLS,
    .stun_keepalive_interval = 25,
    .stun_config = {
        STUN_DEFAULT_RTO,
        STUN_DEFAULT_RC,
        STUN_DEFAULT_RM,
        STUN_DEFAULT_TI,
        0x00
    }
};

/*
 * Default certificate options.
 */
struct rawrtc_certificate_options rawrtc_default_certificate_options = {
    .key_type = RAWRTC_CERTIFICATE_KEY_TYPE_EC,
    .common_name = "anonymous@rawrtc.org",
    .valid_until = 3600 * 24 * 30, // 30 days
    .sign_algorithm = RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
    .named_curve = "prime256v1",
    .modulus_length = 2048
};

/*
 * Default data channel options.
 */
struct rawrtc_data_channel_options rawrtc_default_data_channel_options = {
    .deliver_partially = false
};

/*
 * Translate a rawrtc return code to a string.
 */
char const* rawrtc_code_to_str(
        enum rawrtc_code const code
) {
    switch (code) {
        case RAWRTC_CODE_UNKNOWN_ERROR:
            return "unknown error";
        case RAWRTC_CODE_NOT_IMPLEMENTED:
            return "not implemented";
        case RAWRTC_CODE_SUCCESS:
            return "success";
        case RAWRTC_CODE_INITIALISE_FAIL:
            return "failed to initialise";
        case RAWRTC_CODE_INVALID_ARGUMENT:
            return "invalid argument";
        case RAWRTC_CODE_NO_MEMORY:
            return "no memory";
        case RAWRTC_CODE_INVALID_STATE:
            return "invalid state";
        case RAWRTC_CODE_UNSUPPORTED_PROTOCOL:
            return "unsupported protocol";
        case RAWRTC_CODE_UNSUPPORTED_ALGORITHM:
            return "unsupported algorithm";
        case RAWRTC_CODE_NO_VALUE:
            return "no value";
        case RAWRTC_CODE_NO_SOCKET:
            return "no socket";
        case RAWRTC_CODE_INVALID_CERTIFICATE:
            return "invalid certificate";
        case RAWRTC_CODE_INVALID_FINGERPRINT:
            return "invalid fingerprint";
        case RAWRTC_CODE_INSUFFICIENT_SPACE:
            return "insufficient space";
        case RAWRTC_CODE_STILL_IN_USE:
            return "still in use";
        case RAWRTC_CODE_INVALID_MESSAGE:
            return "invalid message";
        case RAWRTC_CODE_MESSAGE_TOO_LONG:
            return "message too long";
        case RAWRTC_CODE_TRY_AGAIN_LATER:
            return "try again later";
        case RAWRTC_CODE_STOP_ITERATION:
            return "stop iteration";
        case RAWRTC_CODE_NOT_PERMITTED:
            return "not permitted";
        default:
            return "(no error translation)";
    }
}

/*
 * Translate an re error to a rawrtc code.
 * TODO: Add codes from trice_lcand_add
 */
enum rawrtc_code rawrtc_error_to_code(
        int const code
) {
    switch (code) {
        case 0:
            return RAWRTC_CODE_SUCCESS;
        case EAGAIN:
#if (EAGAIN != EWOULDBLOCK)
        case EWOULDBLOCK:
#endif
            return RAWRTC_CODE_TRY_AGAIN_LATER;
        case EAUTH:
            return RAWRTC_CODE_INVALID_CERTIFICATE;
        case EBADMSG:
            return RAWRTC_CODE_INVALID_MESSAGE;
        case EINVAL:
            return RAWRTC_CODE_INVALID_ARGUMENT;
        case EMSGSIZE:
            return RAWRTC_CODE_MESSAGE_TOO_LONG;
        case ENOMEM:
            return RAWRTC_CODE_NO_MEMORY;
        case EPERM:
            return RAWRTC_CODE_NOT_PERMITTED;
        default:
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }
}

static enum rawrtc_ice_gather_policy const map_enum_ice_gather_policy[] = {
    RAWRTC_ICE_GATHER_POLICY_ALL,
    RAWRTC_ICE_GATHER_POLICY_NOHOST,
    RAWRTC_ICE_GATHER_POLICY_RELAY
};

static char const * const map_str_ice_gather_policy[] = {
    "all",
    "nohost",
    "relay"
};

static size_t const map_ice_gather_policy_length = ARRAY_SIZE(map_enum_ice_gather_policy);

/*
 * Translate an ICE gather policy to str.
 */
char const * rawrtc_ice_gather_policy_to_str(
        enum rawrtc_ice_gather_policy const policy
) {
    size_t i;

    for (i = 0; i < map_ice_gather_policy_length; ++i) {
        if (map_enum_ice_gather_policy[i] == policy) {
            return map_str_ice_gather_policy[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE gather policy (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_gather_policy(
        enum rawrtc_ice_gather_policy* const policyp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!policyp || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_gather_policy_length; ++i) {
        if (str_casecmp(map_str_ice_gather_policy[i], str) == 0) {
            *policyp = map_enum_ice_gather_policy[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int rawrtc_ice_protocol_to_ipproto(
        enum rawrtc_ice_protocol const protocol
) {
    // No conversion needed
    return (int) protocol;
}

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum rawrtc_code rawrtc_ipproto_to_ice_protocol(
        enum rawrtc_ice_protocol* const protocolp, // de-referenced
        int const ipproto
) {
    // Check arguments
    if (!protocolp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert IPPROTO_*
    switch (ipproto) {
        case IPPROTO_UDP:
            *protocolp = RAWRTC_ICE_PROTOCOL_UDP;
            return RAWRTC_CODE_SUCCESS;
        case IPPROTO_TCP:
            *protocolp = RAWRTC_ICE_PROTOCOL_TCP;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static enum rawrtc_ice_protocol const map_enum_ice_protocol[] = {
    RAWRTC_ICE_PROTOCOL_UDP,
    RAWRTC_ICE_PROTOCOL_TCP,
};

static char const * const map_str_ice_protocol[] = {
    "udp",
    "tcp",
};

static size_t const map_ice_protocol_length = ARRAY_SIZE(map_enum_ice_protocol);

/*
 * Translate an ICE protocol to str.
 */
char const * rawrtc_ice_protocol_to_str(
        enum rawrtc_ice_protocol const protocol
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
enum rawrtc_code rawrtc_str_to_ice_protocol(
        enum rawrtc_ice_protocol* const protocolp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!protocolp || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_protocol_length; ++i) {
        if (str_casecmp(map_str_ice_protocol[i], str) == 0) {
            *protocolp = map_enum_ice_protocol[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE candidate type to the corresponding re type.
 */
enum ice_cand_type rawrtc_ice_candidate_type_to_ice_cand_type(
        enum rawrtc_ice_candidate_type const type
) {
    // No conversion needed
    return (enum ice_cand_type) type;
}

/*
 * Translate a re ICE candidate type to the corresponding rawrtc type.
 */
enum rawrtc_code rawrtc_ice_cand_type_to_ice_candidate_type(
        enum rawrtc_ice_candidate_type* const typep, // de-referenced
        enum ice_cand_type const re_type
) {
    // Check arguments
    if (!typep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case ICE_CAND_TYPE_HOST:
            *typep = RAWRTC_ICE_CANDIDATE_TYPE_HOST;
            return RAWRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_SRFLX:
            *typep = RAWRTC_ICE_CANDIDATE_TYPE_SRFLX;
            return RAWRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_PRFLX:
            *typep = RAWRTC_ICE_CANDIDATE_TYPE_PRFLX;
            return RAWRTC_CODE_SUCCESS;
        case ICE_CAND_TYPE_RELAY:
            *typep = RAWRTC_ICE_CANDIDATE_TYPE_RELAY;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static enum rawrtc_ice_candidate_type const map_enum_ice_candidate_type[] = {
    RAWRTC_ICE_CANDIDATE_TYPE_HOST,
    RAWRTC_ICE_CANDIDATE_TYPE_SRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_PRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_RELAY,
};

static char const * const map_str_ice_candidate_type[] = {
    "host",
    "srflx",
    "prflx",
    "relay",
};

static size_t const map_ice_candidate_type_length = ARRAY_SIZE(map_enum_ice_candidate_type);

/*
 * Translate an ICE candidate type to str.
 */
char const * rawrtc_ice_candidate_type_to_str(
        enum rawrtc_ice_candidate_type const type
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
enum rawrtc_code rawrtc_str_to_ice_candidate_type(
        enum rawrtc_ice_candidate_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_candidate_type_length; ++i) {
        if (str_casecmp(map_str_ice_candidate_type[i], str) == 0) {
            *typep = map_enum_ice_candidate_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE TCP candidate type to the corresponding re type.
 */
enum ice_tcptype rawrtc_ice_tcp_candidate_type_to_ice_tcptype(
        enum rawrtc_ice_tcp_candidate_type const type
) {
    // No conversion needed
    return (enum ice_tcptype) type;
}

/*
 * Translate a re ICE TCP candidate type to the corresponding rawrtc type.
 */
enum rawrtc_code rawrtc_ice_tcptype_to_ice_tcp_candidate_type(
        enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
        enum ice_tcptype const re_type
) {
    // Check arguments
    if (!typep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert ice_cand_type
    switch (re_type) {
        case ICE_TCP_ACTIVE:
            *typep = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
            return RAWRTC_CODE_SUCCESS;
        case ICE_TCP_PASSIVE:
            *typep = RAWRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE;
            return RAWRTC_CODE_SUCCESS;
        case ICE_TCP_SO:
            *typep = RAWRTC_ICE_TCP_CANDIDATE_TYPE_SO;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static enum rawrtc_ice_tcp_candidate_type const map_enum_ice_tcp_candidate_type[] = {
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_SO,
};

static char const * const map_str_ice_tcp_candidate_type[] = {
    "active",
    "passive",
    "so",
};

static size_t const map_ice_tcp_candidate_type_length = ARRAY_SIZE(map_enum_ice_tcp_candidate_type);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const * rawrtc_ice_tcp_candidate_type_to_str(
        enum rawrtc_ice_tcp_candidate_type const type
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
enum rawrtc_code rawrtc_str_to_ice_tcp_candidate_type(
        enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_tcp_candidate_type_length; ++i) {
        if (str_casecmp(map_str_ice_tcp_candidate_type[i], str) == 0) {
            *typep = map_enum_ice_tcp_candidate_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE role to the corresponding re type.
 */
enum ice_role rawrtc_ice_role_to_re_ice_role(
        enum rawrtc_ice_role const role
) {
    // No conversion needed
    return (enum ice_role) role;
}

/*
 * Translate a re ICE role to the corresponding rawrtc role.
 */
enum rawrtc_code rawrtc_re_ice_role_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        enum ice_role const re_role
) {
    // Check arguments
    if (!rolep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Translate role
    switch (re_role) {
        case ICE_ROLE_CONTROLLING:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLING;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_CONTROLLED:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLED;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_UNKNOWN:
            *rolep = RAWRTC_ICE_ROLE_UNKNOWN;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static enum rawrtc_ice_role const map_enum_ice_role[] = {
    RAWRTC_ICE_ROLE_CONTROLLING,
    RAWRTC_ICE_ROLE_CONTROLLED,
};

static char const * const map_str_ice_role[] = {
    "controlling",
    "controlled",
};

static size_t const map_ice_role_length = ARRAY_SIZE(map_enum_ice_role);

/*
 * Translate an ICE role to str.
 */
char const * rawrtc_ice_role_to_str(
        enum rawrtc_ice_role const role
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
enum rawrtc_code rawrtc_str_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_role_length; ++i) {
        if (str_casecmp(map_str_ice_role[i], str) == 0) {
            *rolep = map_enum_ice_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate a certificate key type to the corresponding re type.
 */
enum tls_keytype rawrtc_certificate_key_type_to_tls_keytype(
        enum rawrtc_certificate_key_type const type
) {
    // No conversion needed
    return (enum tls_keytype) type;
}

static enum rawrtc_dtls_role const map_enum_dtls_role[] = {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER,
};

static char const * const map_str_dtls_role[] = {
    "auto",
    "client",
    "server",
};

static size_t const map_dtls_role_length = ARRAY_SIZE(map_enum_dtls_role);

/*
 * Translate a DTLS role to str.
 */
char const * rawrtc_dtls_role_to_str(
        enum rawrtc_dtls_role const role
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
enum rawrtc_code rawrtc_str_to_dtls_role(
        enum rawrtc_dtls_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (str_casecmp(map_str_dtls_role[i], str) == 0) {
            *rolep = map_enum_dtls_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
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

static enum rawrtc_data_transport_type const map_enum_data_transport_type[] = {
    RAWRTC_DATA_TRANSPORT_TYPE_SCTP,
};

static char const * const map_str_data_transport_type[] = {
    "SCTP",
};

static size_t const map_data_transport_type_length = ARRAY_SIZE(map_enum_data_transport_type);

/*
 * Translate a data transport type to str.
 */
char const * rawrtc_data_transport_type_to_str(
        enum rawrtc_data_transport_type const type
) {
    size_t i;

    for (i = 0; i < map_data_transport_type_length; ++i) {
        if (map_enum_data_transport_type[i] == type) {
            return map_str_data_transport_type[i];
        }
    }

    return "???";
}

/*
 * Get the EVP_MD* structure for a certificate sign algorithm type.
 */
EVP_MD const * const rawrtc_get_sign_function(
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

/*
 * Convert binary to hex string where each value is separated by a
 * colon.
 */
enum rawrtc_code rawrtc_bin_to_colon_hex(
        char** const destinationp, // de-referenced
        uint8_t* const source,
        size_t const length
) {
    char* hex_str;
    char* hex_ptr;
    size_t i;
    int ret;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!destinationp || !source) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate hex string
    hex_str = mem_zalloc(length > 0 ? (length * 3) : 1, NULL);
    if (!hex_str) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Bin to hex
    hex_ptr = hex_str;
    for (i = 0; i < length; ++i) {
        if (i > 0) {
            *hex_ptr = ':';
            ++hex_ptr;
        }
        ret = sprintf(hex_ptr, "%02X", source[i]);
        if (ret != 2) {
            error = RAWRTC_CODE_UNKNOWN_ERROR;
            goto out;
        } else {
            hex_ptr += ret;
        }
    }

out:
    if (error) {
        mem_deref(hex_str);
    } else {
        // Set pointer
        *destinationp = hex_str;
    }
    return error;
}

/*
 * Convert hex string with colon-separated hex values to binary.
 */
enum rawrtc_code rawrtc_colon_hex_to_bin(
        size_t* const bytes_written, // de-referenced
        uint8_t* const buffer, // written into
        size_t const buffer_size,
        char* source
) {
    size_t hex_length;
    size_t bin_length;
    size_t i;

    // Check arguments
    if (!bytes_written || !buffer || !source) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate length
    hex_length = strlen(source);
    if (hex_length > 0 && hex_length % 3 != 2) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Determine size
    bin_length = hex_length > 0 ? (size_t) ((hex_length + 1) / 3) : 0;
    if (bin_length > buffer_size) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Hex to bin
    for (i = 0; i < bin_length; ++i) {
        if (i > 0) {
            // Skip colon
            ++source;
        }
        buffer[i] = ch_hex(*source) << 4;
        ++source;
        buffer[i] += ch_hex(*source);
        ++source;
    }

    // Done
    *bytes_written = bin_length;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the corresponding address family name for an DNS type.
 */
char const * const rawrtc_dns_type_to_address_family_name(
        uint_fast16_t const dns_type
) {
    switch (dns_type) {
        case DNS_TYPE_A:
            return "IPv4";
        case DNS_TYPE_AAAA:
            return "IPv6";
        default:
            return "???";
    }
}

/*
 * Duplicate a string.
 */
enum rawrtc_code rawrtc_strdup(
        char** const destinationp,
        char const * const source
) {
    int err = str_dup(destinationp, source);
    return rawrtc_error_to_code(err);
}

/*
 * Print a formatted string to a buffer.
 */
enum rawrtc_code rawrtc_snprintf(
        char* const destinationp,
        size_t const size,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsnprintf(destinationp, size, formatter, args);
    va_end(args);

    // For some reason, re_vsnprintf does return -1 on argument error
    switch (err) {
        case -1:
            return RAWRTC_CODE_INVALID_ARGUMENT;
        default:
            return rawrtc_error_to_code(err);
    }
}

/*
 * Print a formatted string to a dynamically allocated buffer.
 */
enum rawrtc_code rawrtc_sdprintf(
        char** const destinationp,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsdprintf(destinationp, formatter, args);
    va_end(args);
    return rawrtc_error_to_code(err);
}
