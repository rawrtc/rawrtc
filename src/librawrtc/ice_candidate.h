#pragma once
#include <rawrtc.h>

// Note: Cannot be public until it uses fixed size types in signature (stdint)
uint32_t rawrtc_ice_candidate_calculate_priority(
    enum ice_cand_type const candidate_type,
    int const protocol,
    int const address_family,
    enum ice_tcptype const tcp_type
);

enum rawrtc_code rawrtc_ice_candidate_create_from_remote_candidate(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_rcand* const remote_candidate // referenced
);

enum rawrtc_code rawrtc_ice_candidate_create_from_local_candidate(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_lcand* const local_candidate // referenced
);
