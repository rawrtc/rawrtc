#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <rawrtc.h>
#include "ice_candidate.h"

#define DEBUG_MODULE "ice-candidate"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

static enum rawrtc_ice_candidate_storage const map_enum_ice_candidate_storage[] = {
    RAWRTC_ICE_CANDIDATE_STORAGE_RAW,
    RAWRTC_ICE_CANDIDATE_STORAGE_LCAND,
    RAWRTC_ICE_CANDIDATE_STORAGE_RCAND,
};

static char const * const map_str_ice_candidate_storage[] = {
    "raw",
    "lcand",
    "rcand",
};

static size_t const map_ice_candidate_storage_length = ARRAY_SIZE(map_enum_ice_candidate_storage);

/*
 * Translate an ICE candidate storage type to str.
 */
static char const * ice_candidate_storage_to_str(
        enum rawrtc_ice_candidate_storage const type
) {
    size_t i;

    for (i = 0; i < map_ice_candidate_storage_length; ++i) {
        if (map_enum_ice_candidate_storage[i] == type) {
            return map_str_ice_candidate_storage[i];
        }
    }

    return "???";
}

/*
 * Calculate the ICE candidate priority.
 * TODO: Update argument types, use own
 * TODO: https://tools.ietf.org/html/draft-ietf-ice-rfc5245bis-04#section-4.1.2.1
 */
uint32_t rawrtc_ice_candidate_calculate_priority(
        enum ice_cand_type const candidate_type,
        int const protocol,
        int const address_family,
        enum ice_tcptype const tcp_type
) {
    (void) candidate_type; (void) protocol; (void) address_family; (void) tcp_type;
    return 1;
}

/*
 * Destructor for an existing ICE candidate.
 */
static void rawrtc_ice_candidate_raw_destroy(
        void* arg
) {
    struct rawrtc_ice_candidate_raw* const candidate = arg;

    // Un-reference
    mem_deref(candidate->related_address);
    mem_deref(candidate->ip);
    mem_deref(candidate->foundation);
}

/*
 * Create a raw ICE candidate (pending candidate).
 */
static enum rawrtc_code rawrtc_ice_candidate_raw_create(
        struct rawrtc_ice_candidate_raw** const candidatep, // de-referenced
        struct pl* const foundation, // copied
        uint32_t const priority,
        struct pl* const ip, // copied
        enum rawrtc_ice_protocol const protocol,
        uint16_t const port,
        enum rawrtc_ice_candidate_type const type,
        enum rawrtc_ice_tcp_candidate_type const tcp_type,
        struct pl* const related_address, // copied, nullable
        uint16_t const related_port
) {
    struct rawrtc_ice_candidate_raw* candidate;
    enum rawrtc_code error;

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_ice_candidate_raw_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    error = rawrtc_error_to_code(pl_strdup(&candidate->foundation, foundation));
    if (error) {
        goto out;
    }
    candidate->priority = priority;
    error = rawrtc_error_to_code(pl_strdup(&candidate->ip, ip));
    if (error) {
        goto out;
    }
    candidate->protocol = protocol;
    candidate->port = port;
    candidate->type = type;
    candidate->tcp_type = tcp_type;
    if (pl_isset(related_address)) {
        error = rawrtc_error_to_code(pl_strdup(&candidate->related_address, related_address));
        if (error) {
            goto out;
        }
    }
    candidate->related_port = related_port;

out:
    if (error) {
        mem_deref(candidate);
    } else {
        // Set pointer
        *candidatep = candidate;
        DEBUG_PRINTF("Created candidate (raw): %s\n", ip);
    }
    return error;
}

/*
 * Destructor for an existing ICE candidate.
 */
static void rawrtc_ice_candidate_destroy(
        void* arg
) {
    struct rawrtc_ice_candidate* const candidate = arg;

    // Un-reference
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            mem_deref(candidate->candidate.raw_candidate);
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            mem_deref(candidate->candidate.local_candidate);
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            mem_deref(candidate->candidate.remote_candidate);
            break;
    }
}

/*
 * Create an ICE candidate (pl variant).
 */
enum rawrtc_code rawrtc_ice_candidate_create_internal(
        struct rawrtc_ice_candidate** const candidatep, // de-referenced
        struct pl* const foundation, // copied
        uint32_t const priority,
        struct pl* const ip, // copied
        enum rawrtc_ice_protocol const protocol,
        uint16_t const port,
        enum rawrtc_ice_candidate_type const type,
        enum rawrtc_ice_tcp_candidate_type const tcp_type,
        struct pl* const related_address, // copied, nullable
        uint16_t const related_port
) {
    struct rawrtc_ice_candidate* candidate;
    enum rawrtc_code error;

    // Check arguments
    if (!candidatep || !pl_isset(foundation) || !pl_isset(ip)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_ice_candidate_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set storage type
    candidate->storage_type = RAWRTC_ICE_CANDIDATE_STORAGE_RAW;

    // Create raw candidate
    error = rawrtc_ice_candidate_raw_create(
            &candidate->candidate.raw_candidate, foundation, priority, ip, protocol, port,
            type, tcp_type, related_address, related_port);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(candidate);
    } else {
        // Set pointer
        *candidatep = candidate;
    }
    return error;
}

/*
 * Create an ICE candidate.
 * `*candidatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_create(
        struct rawrtc_ice_candidate** const candidatep, // de-referenced
        char* const foundation, // copied
        uint32_t const priority,
        char* const ip, // copied
        enum rawrtc_ice_protocol const protocol,
        uint16_t const port,
        enum rawrtc_ice_candidate_type const type,
        enum rawrtc_ice_tcp_candidate_type const tcp_type,
        char* const related_address, // copied, nullable
        uint16_t const related_port
) {
    struct pl foundation_pl;
    struct pl ip_pl;
    struct pl related_address_pl = PL_INIT;

    // Check arguments
    if (!foundation || !ip) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert str to pl
    pl_set_str(&foundation_pl, foundation);
    pl_set_str(&ip_pl, ip);
    if (related_address) {
        pl_set_str(&related_address_pl, related_address);
    }

    // Create ICE candidate
    return rawrtc_ice_candidate_create_internal(
            candidatep, &foundation_pl, priority, &ip_pl, protocol, port, type, tcp_type,
            &related_address_pl, related_port);
}

/*
 * Create an ICE candidate instance from an existing local candidate.
 */
enum rawrtc_code rawrtc_ice_candidate_create_from_local_candidate(
        struct rawrtc_ice_candidate** const candidatep, // de-referenced
        struct ice_lcand* const local_candidate // referenced
) {
    struct rawrtc_ice_candidate* candidate;

    // Check arguments
    if (!candidatep || !local_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_ice_candidate_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set storage type and reference local candidate
    candidate->storage_type = RAWRTC_ICE_CANDIDATE_STORAGE_LCAND;
    candidate->candidate.local_candidate = mem_ref(local_candidate);

    // Set pointer
    *candidatep = candidate;
    DEBUG_PRINTF("Created candidate (lcand): %J\n",
                 &candidate->candidate.local_candidate->attr.addr);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create an ICE candidate instance from an existing remote candidate.
 */
enum rawrtc_code rawrtc_ice_candidate_create_from_remote_candidate(
        struct rawrtc_ice_candidate** const candidatep, // de-referenced
        struct ice_rcand* const remote_candidate // referenced
) {
    struct rawrtc_ice_candidate* candidate;

    // Check arguments
    if (!candidatep || !remote_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_ice_candidate_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set storage type and reference remote candidate
    candidate->storage_type = RAWRTC_ICE_CANDIDATE_STORAGE_RCAND;
    candidate->candidate.remote_candidate = mem_ref(remote_candidate);

    // Set pointer
    *candidatep = candidate;
    DEBUG_PRINTF("Created candidate (rcand): %j\n",
                 &candidate->candidate.remote_candidate->attr.addr);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Print debug information for an ICE candidate.
 */
int rawrtc_ice_candidate_debug(
        struct re_printf* const pf,
        struct rawrtc_ice_candidate* const candidate
) {
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
            pf, "    storage_type=%s\n",
            ice_candidate_storage_to_str(candidate->storage_type));

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
    err |= re_hprintf(pf, "    priority=%"PRIu32"\n", priority);

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
    err |= re_hprintf(pf, "    port=%"PRIu16"\n", port);

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
            break;
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
            break;
    }

    // Related port (if any)
    err |= re_hprintf(pf, "    related_port=");
    error = rawrtc_ice_candidate_get_related_port(&related_port, candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            err |= re_hprintf(pf, "%"PRIu16"\n", related_port);
            break;
        case RAWRTC_CODE_NO_VALUE:
            err |= re_hprintf(pf, "n/a\n");
            break;
        default:
            goto out;
            break;
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

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the foundation that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_foundation(
        char** const foundationp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    // Check arguments
    if (!candidate || !foundationp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied foundation
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            return rawrtc_strdup(foundationp, candidate->candidate.raw_candidate->foundation);
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return rawrtc_strdup(
                    foundationp, candidate->candidate.local_candidate->attr.foundation);
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return rawrtc_strdup(
                    foundationp, candidate->candidate.remote_candidate->attr.foundation);
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's priority.
 */
enum rawrtc_code rawrtc_ice_candidate_get_priority(
        uint32_t* const priorityp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    // Check arguments
    if (!candidate || !priorityp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set priority
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *priorityp = candidate->candidate.raw_candidate->priority;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            *priorityp = candidate->candidate.local_candidate->attr.prio;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            *priorityp = candidate->candidate.remote_candidate->attr.prio;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_ip(
        char** const ipp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    // Check arguments
    if (!candidate || !ipp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied IP address
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            return rawrtc_strdup(ipp, candidate->candidate.raw_candidate->ip);
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return rawrtc_sdprintf(ipp, "%j", &candidate->candidate.local_candidate->attr.addr);
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return rawrtc_sdprintf(ipp, "%j", &candidate->candidate.remote_candidate->attr.addr);
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's protocol.
 */
enum rawrtc_code rawrtc_ice_candidate_get_protocol(
        enum rawrtc_ice_protocol* const protocolp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    int ipproto;

    // Check arguments
    if (!candidate || !protocolp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set protocol
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *protocolp = candidate->candidate.raw_candidate->protocol;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            ipproto = candidate->candidate.local_candidate->attr.proto;
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            ipproto = candidate->candidate.remote_candidate->attr.proto;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
    return rawrtc_ipproto_to_ice_protocol(protocolp, ipproto);
}

/*
 * Get the ICE candidate's port.
 */
enum rawrtc_code rawrtc_ice_candidate_get_port(
        uint16_t* const portp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    // Check arguments
    if (!candidate || !portp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *portp = candidate->candidate.raw_candidate->port;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            *portp = sa_port(&candidate->candidate.local_candidate->attr.addr);
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            *portp = sa_port(&candidate->candidate.remote_candidate->attr.addr);
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's type.
 */
enum rawrtc_code rawrtc_ice_candidate_get_type(
        enum rawrtc_ice_candidate_type* typep, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    // Check arguments
    if (!candidate || !typep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set type
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *typep = candidate->candidate.raw_candidate->type;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return rawrtc_ice_cand_type_to_ice_candidate_type(
                    typep, candidate->candidate.local_candidate->attr.type);
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return rawrtc_ice_cand_type_to_ice_candidate_type(
                    typep, candidate->candidate.remote_candidate->attr.type);
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's TCP type.
 * Return `RAWRTC_CODE_NO_VALUE` in case the protocol is not TCP.
 */
enum rawrtc_code rawrtc_ice_candidate_get_tcp_type(
        enum rawrtc_ice_tcp_candidate_type* typep, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    struct ice_cand_attr* re_candidate;

    // Check arguments
    if (!candidate || !typep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set type/get re candidate
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *typep = candidate->candidate.raw_candidate->tcp_type;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // Set type from re candidate if TCP
    if (re_candidate->proto == IPPROTO_TCP) {
        return rawrtc_ice_tcptype_to_ice_tcp_candidate_type(typep, re_candidate->tcptype);
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related address exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_address(
        char** const related_addressp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    struct ice_cand_attr* re_candidate = NULL;

    // Check arguments
    if (!candidate || !related_addressp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied related IP address/get re candidate
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            if (candidate->candidate.raw_candidate->related_address) {
                return rawrtc_strdup(
                        related_addressp, candidate->candidate.raw_candidate->related_address);
            }
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // Set copied related IP address from re candidate
    if (re_candidate && sa_isset(&re_candidate->rel_addr, SA_ADDR)) {
        return rawrtc_sdprintf(
                related_addressp, "%j", &candidate->candidate.local_candidate->attr.rel_addr);
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related port exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_port(
        uint16_t* const related_portp, // de-referenced
        struct rawrtc_ice_candidate* const candidate
) {
    struct ice_cand_attr* re_candidate = NULL;

    // Check arguments
    if (!candidate || !related_portp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            if (candidate->candidate.raw_candidate->related_address) {
                *related_portp = candidate->candidate.raw_candidate->related_port;
                return RAWRTC_CODE_SUCCESS;
            }
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case RAWRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // Set copied related IP address' port from re candidate
    if (re_candidate && sa_isset(&re_candidate->rel_addr, SA_PORT)) {
        *related_portp = sa_port(&candidate->candidate.local_candidate->attr.rel_addr);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
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
 * Translate a pl to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_protocol(
        enum rawrtc_ice_protocol* const protocolp, // de-referenced
        struct pl const* const pl
) {
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
        enum rawrtc_ice_protocol* const protocolp, // de-referenced
        char const* const str
) {
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
 * Translate a pl to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_candidate_type(
        enum rawrtc_ice_candidate_type* const typep, // de-referenced
        struct pl const* const pl
) {
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
        enum rawrtc_ice_candidate_type* const typep, // de-referenced
        char const* const str
) {
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
enum rawrtc_code rawrtc_pl_to_ice_tcp_candidate_type(
        enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
        struct pl const* const pl
) {
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
        enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
        char const* const str
) {
    struct pl pl;

    // Check arguments
    if (!str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert str to pl
    pl_set_str(&pl, str);
    return rawrtc_pl_to_ice_tcp_candidate_type(typep, &pl);
}
