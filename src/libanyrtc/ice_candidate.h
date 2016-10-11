#pragma once

uint32_t anyrtc_ice_candidate_calculate_priority(
    enum ice_cand_type const candidate_type,
    int const protocol,
    enum ice_tcptype const tcp_type
);
