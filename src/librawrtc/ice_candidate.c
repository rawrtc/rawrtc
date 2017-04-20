#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <rawrtc.h>
#include "ice_candidate.h"
#include "utils.h"

#define DEBUG_MODULE "ice-candidate"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

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
    struct rawrtc_ice_candidate_raw* candidate;
    enum rawrtc_code error;

    // Allocate
    candidate = mem_zalloc(sizeof(*candidate), rawrtc_ice_candidate_raw_destroy);
    if (!candidate) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    error = rawrtc_strdup(&candidate->foundation, foundation);
    if (error) {
        goto out;
    }
    candidate->priority = priority;
    error = rawrtc_strdup(&candidate->ip, ip);
    if (error) {
        goto out;
    }
    candidate->protocol = protocol;
    candidate->port = port;
    candidate->type = type;
    candidate->tcp_type = tcp_type;
    if (related_address) {
        error = rawrtc_strdup(&candidate->related_address, related_address);
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
 * Create an ICE candidate.
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
        char* const related_address, // copied
        uint16_t const related_port
) {
    struct rawrtc_ice_candidate* candidate;
    enum rawrtc_code error;

    // Check arguments
    if (!candidatep || !foundation || !ip) {
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
