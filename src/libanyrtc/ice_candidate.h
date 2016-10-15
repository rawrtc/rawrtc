#pragma once

uint32_t anyrtc_ice_candidate_calculate_priority(
    enum ice_cand_type const candidate_type,
    int const protocol,
    enum ice_tcptype const tcp_type
);

enum anyrtc_code anyrtc_ice_candidate_create_from_remote_candidate(
    struct anyrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_rcand* const remote_candidate // referenced
);

enum anyrtc_code anyrtc_ice_candidate_create_from_local_candidate(
    struct anyrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_lcand* const local_candidate // referenced
);
