#include "candidate.h"
#include <rawrtc/config.h>
#include <rawrtc/ice_candidate.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>
#include <rew.h>

#define DEBUG_MODULE "ice-candidate"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

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
