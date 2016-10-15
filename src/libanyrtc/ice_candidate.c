#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <anyrtc.h>
#include "ice_candidate.h"
#include "utils.h"

#define DEBUG_MODULE "ice-candidate"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Calculate the ICE candidate priority.
 * TODO: https://tools.ietf.org/html/draft-ietf-ice-rfc5245bis-04#section-4.1.2.1
 */
uint32_t anyrtc_ice_candidate_calculate_priority(
        enum ice_cand_type const candidate_type,
        int const protocol,
        enum ice_tcptype const tcp_type
) {
    return 0;
}

/*
 * Destructor for an existing ICE candidate.
 */
static void anyrtc_ice_candidate_raw_destroy(void *arg) {
    struct anyrtc_ice_candidate_raw* candidate = arg;

    // Dereference
    mem_deref(candidate->related_address);
    mem_deref(candidate->ip);
    mem_deref(candidate->foundation);
}

/*
 * Create a raw ICE candidate (pending candidate).
 */
static enum anyrtc_code anyrtc_ice_candidate_raw_create(
        struct anyrtc_ice_candidate_raw** const candidatep, // de-referenced
        char* const foundation, // copied
        uint32_t const priority,
        char* const ip, // copied
        enum anyrtc_ice_protocol const protocol,
        uint16_t const port,
        enum anyrtc_ice_candidate_type const type,
        enum anyrtc_ice_tcp_candidate_type const tcp_type,
        char* const related_address, // copied, nullable
        uint16_t const related_port
) {
    struct anyrtc_ice_candidate_raw* candidate;
    enum anyrtc_code error;

    // Allocate
    candidate = mem_alloc(sizeof(struct anyrtc_ice_candidate_raw),
                          anyrtc_ice_candidate_raw_destroy);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/copy
    error = anyrtc_strdup(&candidate->foundation, foundation);
    if (error) {
        goto out;
    }
    candidate->priority = priority;
    error = anyrtc_strdup(&candidate->ip, ip);
    if (error) {
        goto out;
    }
    candidate->protocol = protocol;
    candidate->port = port;
    candidate->type = type;
    candidate->tcp_type = tcp_type;
    if (related_address) {
        error = anyrtc_strdup(&candidate->related_address, related_address);
        if (error) {
            goto out;
        }
    }
    candidate->related_port = related_port;

out:
    if (error) {
        mem_deref(candidate->related_address);
        mem_deref(candidate->ip);
        mem_deref(candidate->foundation);
        mem_deref(candidate);
    } else {
        // Set pointer
        *candidatep = candidate;
    }
    return error;
}

/*
 * Destructor for an existing ICE candidate.
 */
static void anyrtc_ice_candidate_destroy(void *arg) {
    struct anyrtc_ice_candidate* candidate = arg;

    // Dereference
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            mem_deref(candidate->candidate.raw_candidate);
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            mem_deref(candidate->candidate.local_candidate);
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            mem_deref(candidate->candidate.remote_candidate);
            break;
    }
}

/*
 * Create an ICE candidate.
 */
enum anyrtc_code anyrtc_ice_candidate_create(
        struct anyrtc_ice_candidate** const candidatep, // de-referenced
        char* const foundation, // copied
        uint32_t const priority,
        char* const ip, // copied
        enum anyrtc_ice_protocol const protocol,
        uint16_t const port,
        enum anyrtc_ice_candidate_type const type,
        enum anyrtc_ice_tcp_candidate_type const tcp_type,
        char* const related_address, // copied
        uint16_t const related_port
) {
    struct anyrtc_ice_candidate* candidate;
    enum anyrtc_code error;

    // Check arguments
    if (!candidatep || !foundation || !ip || !related_address) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    candidate = mem_alloc(sizeof(struct anyrtc_ice_candidate), anyrtc_ice_candidate_destroy);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set storage type
    candidate->storage_type = ANYRTC_ICE_CANDIDATE_STORAGE_RAW;

    // Create raw candidate
    error = anyrtc_ice_candidate_raw_create(
            &candidate->candidate.raw_candidate, foundation, priority, ip, protocol, port,
            type, tcp_type, related_address, related_port);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(candidate->candidate.raw_candidate);
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
enum anyrtc_code anyrtc_ice_candidate_create_from_local_candidate(
        struct anyrtc_ice_candidate** const candidatep, // de-referenced
        struct ice_lcand* const local_candidate // referenced
) {
    struct anyrtc_ice_candidate* candidate;

    // Allocate
    candidate = mem_zalloc(sizeof(struct anyrtc_ice_candidate), anyrtc_ice_candidate_destroy);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set storage type and reference local candidate
    candidate->storage_type = ANYRTC_ICE_CANDIDATE_STORAGE_LCAND;
    candidate->candidate.local_candidate = mem_ref(local_candidate);

    // Set pointer
    *candidatep = candidate;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Create an ICE candidate instance from an existing remote candidate.
 */
enum anyrtc_code anyrtc_ice_candidate_create_from_remote_candidate(
        struct anyrtc_ice_candidate** const candidatep, // de-referenced
        struct ice_rcand* const remote_candidate // referenced
) {
    struct anyrtc_ice_candidate* candidate;

    // Allocate
    candidate = mem_zalloc(sizeof(struct anyrtc_ice_candidate), anyrtc_ice_candidate_destroy);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set storage type and reference remote candidate
    candidate->storage_type = ANYRTC_ICE_CANDIDATE_STORAGE_RCAND;
    candidate->candidate.remote_candidate = mem_ref(remote_candidate);

    // Set pointer
    *candidatep = candidate;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum anyrtc_code anyrtc_ice_candidate_get_foundation(
        struct anyrtc_ice_candidate* const candidate,
        char** const foundationp // de-referenced
) {
    // Check arguments
    if (!candidate || !foundationp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied foundation
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            return anyrtc_strdup(foundationp, candidate->candidate.raw_candidate->foundation);
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return anyrtc_strdup(
                    foundationp, candidate->candidate.local_candidate->attr.foundation);
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return anyrtc_strdup(
                    foundationp, candidate->candidate.remote_candidate->attr.foundation);
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's priority.
 */
enum anyrtc_code anyrtc_ice_candidate_get_priority(
        struct anyrtc_ice_candidate* const candidate,
        uint32_t* const priorityp // de-referenced
) {
    // Check arguments
    if (!candidate || !priorityp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set priority
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            *priorityp = candidate->candidate.raw_candidate->priority;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            *priorityp = candidate->candidate.local_candidate->attr.prio;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            *priorityp = candidate->candidate.remote_candidate->attr.prio;
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum anyrtc_code anyrtc_ice_candidate_get_ip(
        struct anyrtc_ice_candidate* const candidate,
        char** const ipp // de-referenced
) {
    // Check arguments
    if (!candidate || !ipp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied IP address
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            return anyrtc_strdup(ipp, candidate->candidate.raw_candidate->ip);
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return anyrtc_sdprintf(ipp, "%j", candidate->candidate.local_candidate->attr.addr);
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return anyrtc_sdprintf(ipp, "%j", candidate->candidate.remote_candidate->attr.addr);
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's protocol.
 */
enum anyrtc_code anyrtc_ice_candidate_get_protocol(
        struct anyrtc_ice_candidate* const candidate,
        enum anyrtc_ice_protocol* const protocolp // de-referenced
) {
    int ipproto;

    // Check arguments
    if (!candidate || !protocolp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set protocol
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            *protocolp = candidate->candidate.raw_candidate->protocol;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            ipproto = candidate->candidate.local_candidate->attr.proto;
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            ipproto = candidate->candidate.remote_candidate->attr.proto;
            break;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
    return anyrtc_translate_ipproto(ipproto, protocolp);
}

/*
 * Get the ICE candidate's port.
 */
enum anyrtc_code anyrtc_ice_candidate_get_port(
        struct anyrtc_ice_candidate* const candidate,
        uint16_t* const portp // de-referenced
) {
    // Check arguments
    if (!candidate || !portp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            *portp = candidate->candidate.raw_candidate->port;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            *portp = sa_port(&candidate->candidate.local_candidate->attr.addr);
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            *portp = sa_port(&candidate->candidate.remote_candidate->attr.addr);
            return ANYRTC_CODE_SUCCESS;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's type.
 */
enum anyrtc_code anyrtc_ice_candidate_get_type(
        struct anyrtc_ice_candidate* const candidate,
        enum anyrtc_ice_candidate_type* typep // de-referenced
) {
    // Check arguments
    if (!candidate || !typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set type
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            *typep = candidate->candidate.raw_candidate->type;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            return anyrtc_translate_re_ice_cand_type(
                    candidate->candidate.local_candidate->attr.type, typep);
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            return anyrtc_translate_re_ice_cand_type(
                    candidate->candidate.remote_candidate->attr.type, typep);
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }
}

/*
 * Get the ICE candidate's TCP type.
 * Return `ANYRTC_CODE_NO_VALUE` in case the protocol is not TCP.
 */
enum anyrtc_code anyrtc_ice_candidate_get_tcp_type(
        struct anyrtc_ice_candidate* const candidate,
        enum anyrtc_ice_tcp_candidate_type* typep // de-referenced
) {
    struct ice_cand_attr* re_candidate;

    // Check arguments
    if (!candidate || !typep) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set type/get re candidate
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            *typep = candidate->candidate.raw_candidate->tcp_type;
            return ANYRTC_CODE_SUCCESS;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }

    // Set type from re candidate if TCP
    if (re_candidate->proto == IPPROTO_TCP) {
        return anyrtc_translate_re_ice_tcptype(re_candidate->tcptype, typep);
    } else {
        return ANYRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced.
 *
 * Return `ANYRTC_CODE_NO_VALUE` in case no related address exists.
 */
enum anyrtc_code anyrtc_ice_candidate_get_related_address(
        struct anyrtc_ice_candidate* const candidate,
        char** const related_addressp // de-referenced
) {
    struct ice_cand_attr* re_candidate = NULL;

    // Check arguments
    if (!candidate || !related_addressp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set copied related IP address/get re candidate
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            if (candidate->candidate.raw_candidate->related_address) {
                return anyrtc_strdup(
                        related_addressp, candidate->candidate.raw_candidate->related_address);
            }
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }

    // Set copied related IP address from re candidate
    if (re_candidate && sa_isset(&re_candidate->rel_addr, SA_ADDR)) {
        return anyrtc_sdprintf(
                related_addressp, "%j", candidate->candidate.local_candidate->attr.rel_addr);
    } else {
        return ANYRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port.
 *
 * Return `ANYRTC_CODE_NO_VALUE` in case no related port exists.
 */
enum anyrtc_code anyrtc_ice_candidate_get_related_port(
        struct anyrtc_ice_candidate* const candidate,
        uint16_t* const related_portp // de-referenced
) {
    struct ice_cand_attr* re_candidate = NULL;

    // Check arguments
    if (!candidate || !related_portp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    switch (candidate->storage_type) {
        case ANYRTC_ICE_CANDIDATE_STORAGE_RAW:
            if (candidate->candidate.raw_candidate->related_address) {
                *related_portp = candidate->candidate.raw_candidate->related_port;
                return ANYRTC_CODE_SUCCESS;
            }
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_LCAND:
            re_candidate = &candidate->candidate.local_candidate->attr;
            break;
        case ANYRTC_ICE_CANDIDATE_STORAGE_RCAND:
            re_candidate = &candidate->candidate.remote_candidate->attr;
            break;
        default:
            return ANYRTC_CODE_INVALID_STATE;
    }

    // Set copied related IP address' port from re candidate
    if (re_candidate && sa_isset(&re_candidate->rel_addr, SA_PORT)) {
        *related_portp = sa_port(&candidate->candidate.local_candidate->attr.rel_addr);
        return ANYRTC_CODE_SUCCESS;
    } else {
        return ANYRTC_CODE_NO_VALUE;
    }
}
