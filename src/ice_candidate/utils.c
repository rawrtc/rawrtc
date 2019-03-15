#include "candidate.h"
#include <rawrtc/ice_candidate.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <netinet/in.h>  // IPPROTO_UDP, IPPROTO_TCP

/*
 * Translate an ICE candidate type to the corresponding re type.
 */
enum ice_cand_type rawrtc_ice_candidate_type_to_ice_cand_type(
    enum rawrtc_ice_candidate_type const type) {
    // No conversion needed
    return (enum ice_cand_type) type;
}

/*
 * Translate a re ICE candidate type to the corresponding rawrtc type.
 */
enum rawrtc_code rawrtc_ice_cand_type_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep,  // de-referenced
    enum ice_cand_type const re_type) {
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

/*
 * Translate an ICE TCP candidate type to the corresponding re type.
 */
enum ice_tcptype rawrtc_ice_tcp_candidate_type_to_ice_tcptype(
    enum rawrtc_ice_tcp_candidate_type const type) {
    // No conversion needed
    return (enum ice_tcptype) type;
}

/*
 * Translate a re ICE TCP candidate type to the corresponding rawrtc type.
 */
enum rawrtc_code rawrtc_ice_tcptype_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep,  // de-referenced
    enum ice_tcptype const re_type) {
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

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int rawrtc_ice_protocol_to_ipproto(enum rawrtc_ice_protocol const protocol) {
    // No conversion needed
    return (int) protocol;
}

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum rawrtc_code rawrtc_ipproto_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    int const ipproto) {
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

static char const* const map_str_ice_protocol[] = {
    "udp",
    "tcp",
};

static size_t const map_ice_protocol_length = ARRAY_SIZE(map_enum_ice_protocol);

/*
 * Translate an ICE protocol to str.
 */
char const* rawrtc_ice_protocol_to_str(enum rawrtc_ice_protocol const protocol) {
    size_t i;

    for (i = 0; i < map_ice_protocol_length; ++i) {
        if (map_enum_ice_protocol[i] == protocol) {
            return map_str_ice_protocol[i];
        }
    }

    return "???";
}

/*
 * Translate a pl to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    struct pl const* const pl) {
    size_t i;

    // Check arguments
    if (!protocolp || !pl_isset(pl)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_protocol_length; ++i) {
        if (pl_strcasecmp(pl, map_str_ice_protocol[i]) == 0) {
            *protocolp = map_enum_ice_protocol[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate a str to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    char const* const str) {
    struct pl pl;

    // Check arguments
    if (!str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert str to pl
    pl_set_str(&pl, str);
    return rawrtc_pl_to_ice_protocol(protocolp, &pl);
}

static enum rawrtc_ice_candidate_type const map_enum_ice_candidate_type[] = {
    RAWRTC_ICE_CANDIDATE_TYPE_HOST,
    RAWRTC_ICE_CANDIDATE_TYPE_SRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_PRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_RELAY,
};

static char const* const map_str_ice_candidate_type[] = {
    "host",
    "srflx",
    "prflx",
    "relay",
};

static size_t const map_ice_candidate_type_length = ARRAY_SIZE(map_enum_ice_candidate_type);

/*
 * Translate an ICE candidate type to str.
 */
char const* rawrtc_ice_candidate_type_to_str(enum rawrtc_ice_candidate_type const type) {
    size_t i;

    for (i = 0; i < map_ice_candidate_type_length; ++i) {
        if (map_enum_ice_candidate_type[i] == type) {
            return map_str_ice_candidate_type[i];
        }
    }

    return "???";
}

/*
 * Translate a pl to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep,  // de-referenced
    struct pl const* const pl) {
    size_t i;

    // Check arguments
    if (!typep || !pl_isset(pl)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_candidate_type_length; ++i) {
        if (pl_strcasecmp(pl, map_str_ice_candidate_type[i]) == 0) {
            *typep = map_enum_ice_candidate_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate a str to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep,  // de-referenced
    char const* const str) {
    struct pl pl;

    // Check arguments
    if (!str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert str to pl
    pl_set_str(&pl, str);
    return rawrtc_pl_to_ice_candidate_type(typep, &pl);
}

static enum rawrtc_ice_tcp_candidate_type const map_enum_ice_tcp_candidate_type[] = {
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_SO,
};

static char const* const map_str_ice_tcp_candidate_type[] = {
    "active",
    "passive",
    "so",
};

static size_t const map_ice_tcp_candidate_type_length = ARRAY_SIZE(map_enum_ice_tcp_candidate_type);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const* rawrtc_ice_tcp_candidate_type_to_str(enum rawrtc_ice_tcp_candidate_type const type) {
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
enum rawrtc_code rawrtc_pl_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep,  // de-referenced
    struct pl const* const pl) {
    size_t i;

    // Check arguments
    if (!typep || !pl_isset(pl)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_tcp_candidate_type_length; ++i) {
        if (pl_strcasecmp(pl, map_str_ice_tcp_candidate_type[i]) == 0) {
            *typep = map_enum_ice_tcp_candidate_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep,  // de-referenced
    char const* const str) {
    struct pl pl;

    // Check arguments
    if (!str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert str to pl
    pl_set_str(&pl, str);
    return rawrtc_pl_to_ice_tcp_candidate_type(typep, &pl);
}

static char const* const map_str_ice_candidate_storage[] = {
    "raw",
    "lcand",
    "rcand",
};

static enum rawrtc_ice_candidate_storage const map_enum_ice_candidate_storage[] = {
    RAWRTC_ICE_CANDIDATE_STORAGE_RAW,
    RAWRTC_ICE_CANDIDATE_STORAGE_LCAND,
    RAWRTC_ICE_CANDIDATE_STORAGE_RCAND,
};

static size_t const map_ice_candidate_storage_length = ARRAY_SIZE(map_enum_ice_candidate_storage);

/*
 * Translate an ICE candidate storage type to str.
 */
static char const* ice_candidate_storage_to_str(enum rawrtc_ice_candidate_storage const type) {
    size_t i;

    for (i = 0; i < map_ice_candidate_storage_length; ++i) {
        if (map_enum_ice_candidate_storage[i] == type) {
            return map_str_ice_candidate_storage[i];
        }
    }

    return "???";
}

/*
 * Print debug information for an ICE candidate.
 */
int rawrtc_ice_candidate_debug(
    struct re_printf* const pf, struct rawrtc_ice_candidate* const candidate) {
    int err = 0;
    enum rawrtc_code error;
    char* foundation = NULL;
    uint32_t priority;
    char* ip = NULL;
    enum rawrtc_ice_protocol protocol;
    uint16_t port;
    enum rawrtc_ice_candidate_type type;
    enum rawrtc_ice_tcp_candidate_type tcp_type;
    char* related_address = NULL;
    uint16_t related_port;

    // Check arguments
    if (!candidate) {
        return 0;
    }

    err |= re_hprintf(pf, "  ICE Candidate <%p>:\n", candidate);

    // Storage type
    err |= re_hprintf(
        pf, "    storage_type=%s\n", ice_candidate_storage_to_str(candidate->storage_type));

    // Foundation
    error = rawrtc_ice_candidate_get_foundation(&foundation, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    foundation=\"%s\"\n", foundation);

    // Priority
    error = rawrtc_ice_candidate_get_priority(&priority, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    priority=%" PRIu32 "\n", priority);

    // IP
    error = rawrtc_ice_candidate_get_ip(&ip, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    ip=%s\n", ip);

    // Protocol
    error = rawrtc_ice_candidate_get_protocol(&protocol, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    protocol=%s\n", rawrtc_ice_protocol_to_str(protocol));

    // Port
    error = rawrtc_ice_candidate_get_port(&port, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    port=%" PRIu16 "\n", port);

    // Type
    error = rawrtc_ice_candidate_get_type(&type, candidate);
    if (error) {
        goto out;
    }
    err |= re_hprintf(pf, "    type=%s\n", rawrtc_ice_candidate_type_to_str(type));

    // TCP type (if any)
    err |= re_hprintf(pf, "    tcp_type=");
    error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            err |= re_hprintf(pf, "%s\n", rawrtc_ice_tcp_candidate_type_to_str(tcp_type));
            break;
        case RAWRTC_CODE_NO_VALUE:
            err |= re_hprintf(pf, "n/a\n");
            break;
        default:
            goto out;
    }

    // Related address (if any)
    err |= re_hprintf(pf, "    related_address=");
    error = rawrtc_ice_candidate_get_related_address(&related_address, candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            err |= re_hprintf(pf, "%s\n", related_address);
            break;
        case RAWRTC_CODE_NO_VALUE:
            err |= re_hprintf(pf, "n/a\n");
            break;
        default:
            goto out;
    }

    // Related port (if any)
    err |= re_hprintf(pf, "    related_port=");
    error = rawrtc_ice_candidate_get_related_port(&related_port, candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            err |= re_hprintf(pf, "%" PRIu16 "\n", related_port);
            break;
        case RAWRTC_CODE_NO_VALUE:
            err |= re_hprintf(pf, "n/a\n");
            break;
        default:
            goto out;
    }

out:
    // Un-reference
    mem_deref(related_address);
    mem_deref(ip);
    mem_deref(foundation);

    // Translate error & done
    if (!err && error) {
        err = EINVAL;
    }
    return err;
}
