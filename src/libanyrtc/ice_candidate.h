#pragma once
#include <anyrtc.h>

/*
 * Create a new ICE candidate.
 */
enum anyrtc_code anyrtc_ice_candidate_create(
    struct anyrtc_ice_candidate** const candidatep, // de-referenced
    struct anyrtc_ice_gatherer* const gatherer,
    struct sa const* const address,
    enum ice_cand_type const candidate_type,
    int const protocol,
    enum ice_tcptype const tcp_type,
    struct sa const* const related_address // nullable
);
