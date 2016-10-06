#include <netinet/in.h>
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
 * Copied from rew/src/trice/lcand.c as it's not exported and we need it earlier.
 */
static enum anyrtc_code set_foundation(
        char* const foundationp, // de-referenced
        const struct sa const* const address,
        enum ice_cand_type const tcp_type
) {
    uint32_t v;

    /* Foundation is a hash of IP address and candidate type */
    v  = sa_hash(address, SA_ADDR);
    v ^= tcp_type;  // Uh... I hope that's still unique...

    if (re_snprintf(cand->attr.foundation, sizeof(cand->attr.foundation),
                    "%08x", v) < 0)
        return ENOMEM;

    return ANYRTC_CODE_SUCCESS;
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

static void anyrtc_ice_candidate_destroy(void* arg) {
    struct anyrtc_ice_candidate* candidate = arg;

    // Dereference
//    list_flush(&options->ice_servers);
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
        enum ice_tcptype const tcp_type
) {
    enum anyrtc_ice_protocol ice_protocol;
    struct anyrtc_ice_candidate* candidate;
    uint32_t priority;

    // Check arguments
    if (!candidatep || !gatherer || !address) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check protocol (and TCP type)
    if (!is_supported_protocol(protocol, &ice_protocol, tcp_type)) {
        return ANYRTC_CODE_UNSUPPORTED_PROTOCOL;
    }

    // Allocate
    candidate = mem_zalloc(sizeof(struct anyrtc_ice_candidate), anyrtc_ice_candidate_destroy);
    if (!candidate) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Calculate priority
    priority = calculate_candidate_priority(candidate_type, protocol, tcp_type);

    // Create local candidate using librew
    trice_lcand_add(&local_candidate, agent->ice, COMPONENT_ID, protocol,
                    priority, address, NULL, ICE_CAND_TYPE_HOST, NULL, tcp_type, NULL, LAYER_ICE);

    // Set fields/reference
    candidate->is_local = true;
    candidate->local_candidate = mem_ref(local_candidate);

    // Set pointer and return
    *candidatep = candidate;

    DEBUG_PRINTF("Created local candidate %j, type: %s, protocol: %s, priority: %"PRIu32""
                 ", tcp type: %s\n",
                 address, "host", net_proto2name(protocol), priority,
                 protocol == IPPROTO_TCP ? ice_tcptype_name(tcp_type) : "n/a");
    return ANYRTC_CODE_SUCCESS;
    // Add local candidate

    struct ice_lcand* local_candidate;
    int error = trice_lcand_add(&local_candidate, agent->ice, COMPONENT_ID, protocol,
                                priority, address, NULL, ICE_CAND_TYPE_HOST, NULL, tcp_type, NULL, LAYER_ICE);
    if (error) {
        DEBUG_WARNING("Failed to add local candidate (%m)\n", error);
        return error;
    }

    // TODO: Gather srflx candidates
    DEBUG_PRINTF("TODO: Gather srflx candidates for %j\n", address);
    // TODO: Gather relay candidates
    DEBUG_PRINTF("TODO: Gather relay candidates for %j\n", address);

    return error;
}
