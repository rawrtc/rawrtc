#include "candidate.h"
#include <rawrtc/ice_candidate.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>
#include <rew.h>
#include <string.h>  // strlen

// Constants
static char const mdns_hostname_regex[] = "[^\\.]+\\.local";

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the foundation that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_foundation(
    char** const foundationp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    uint32_t* const priorityp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
 * Check if the ICE candidate contains an mDNS address.
 */
enum rawrtc_code rawrtc_ice_candidate_is_mdns_hostname(
    bool* const is_mdnsp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
    // Check arguments
    if (!candidate || !is_mdnsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if it contains an mDNS address
    switch (candidate->storage_type) {
        case RAWRTC_ICE_CANDIDATE_STORAGE_RAW:
            *is_mdnsp =
                re_regex(
                    candidate->candidate.raw_candidate->ip,
                    strlen(candidate->candidate.raw_candidate->ip), mdns_hostname_regex, NULL)
                    ? false
                    : true;
            return RAWRTC_CODE_SUCCESS;
        default:
            return false;
    }
}

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_ip(
    char** const ipp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    uint16_t* const portp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    enum rawrtc_ice_candidate_type* typep,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    enum rawrtc_ice_tcp_candidate_type* typep,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    char** const related_addressp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
    uint16_t* const related_portp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate) {
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
