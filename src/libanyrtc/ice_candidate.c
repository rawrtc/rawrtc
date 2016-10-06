#include <netinet/in.h>
#include <inttypes.h>
#include <anyrtc.h>
#include "ice_candidate.h"
#include "utils.h"

#define DEBUG_MODULE "ice-candidate"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Calculate the ICE candidate priority.
 * TODO: Couldn't find a related RFC/draft, yet. :/
 */
static uint32_t calculate_candidate_priority(
        enum ice_cand_type const candidate_type,
        int const protocol,
        enum ice_tcptype const tcp_type
) {
    return 0;
}

/*
 * Return the foundation of an ICE candidate.
 * Copied from rew/src/trice/lcand.c as it's not exported and we need it earlier.
 */
static uint32_t compute_foundation(
        const struct sa const* const address,
        enum ice_cand_type const tcp_type
) {
    uint32_t hash;

    /* Foundation is a hash of IP address and candidate type */
    hash  = sa_hash(address, SA_ADDR);
    hash ^= tcp_type;  // Uh... I hope that's still unique...

    return hash;
}

/*
 * Check that the protocol (and the TCP type) is supported by our ICE implementation.
 */
static bool is_supported_protocol(
        int const protocol,
        enum anyrtc_ice_protocol * const ice_protocol, // de-referenced
        enum ice_tcptype const tcp_type
) {
    // Check protocol
    switch (protocol) {
        case IPPROTO_UDP:
            *ice_protocol = ANYRTC_ICE_PROTOCOL_UDP;
            return true;
        case IPPROTO_TCP:
            break;
        default:
            return false;
    }

    // Check TCP type
    switch (tcp_type) {
        case ICE_TCP_ACTIVE:
        case ICE_TCP_PASSIVE:
        case ICE_TCP_SO:
//            *ice_protocol = ANYRTC_ICE_PROTOCOL_TCP;
            return false; // TODO: Change to true once we support TCP
        default:
            return false;
    }
}

/*
 * Create a new local ICE candidate.
 */
enum anyrtc_code anyrtc_ice_candidate_create(
        struct anyrtc_ice_candidate** const candidatep, // de-referenced
        struct anyrtc_ice_gatherer* const gatherer,
        struct sa const* const address,
        enum ice_cand_type const candidate_type,
        int const protocol,
        enum ice_tcptype const tcp_type,
        struct sa const* const related_address // nullable
) {
    enum anyrtc_ice_protocol ice_protocol;
    struct anyrtc_ice_candidate* candidate;
    enum anyrtc_code error;

    // Check arguments
    if (!candidatep || !gatherer || !address) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check protocol (and TCP type)
    if (!is_supported_protocol(protocol, &ice_protocol, tcp_type)) {
        return ANYRTC_CODE_UNSUPPORTED_PROTOCOL;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(struct anyrtc_ice_candidate), NULL);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Calculate and set priority
    candidate->priority = calculate_candidate_priority(candidate_type, protocol, tcp_type);

    // Compute and set foundation
    candidate->key = compute_foundation(address, candidate_type);
    error = anyrtc_snprintf(candidate->foundation, sizeof(candidate->foundation),
                            "%08x", candidate->key);
    if (error) {
        goto out;
    }

    // Set fields/reference
    candidate->address = *address;
    candidate->protocol = ice_protocol;
    candidate->type = candidate_type;
    candidate->tcp_type = tcp_type;
    if (related_address) {
        candidate->related_address = *related_address;
    }

    // Set pointer
    *candidatep = candidate;
    DEBUG_PRINTF(
            "Created local candidate %j, type: %s, protocol: %s, priority: %"PRIu32""
            ", tcp type: %s\n",
            address, ice_cand_type2name(candidate_type), net_proto2name(protocol),
            candidate->priority, protocol == IPPROTO_TCP ? ice_tcptype_name(tcp_type) : "n/a");

out:
    if (error) {
        mem_deref(candidate);
    }
    return error;
}
