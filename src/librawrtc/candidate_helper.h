#pragma once

/*
 * Local candidate helper.
 */
struct rawrtc_candidate_helper {
    struct le le;
    struct rawrtc_ice_gatherer* gatherer;
    struct ice_lcand* candidate;
    struct udp_helper* udp_helper;
    uint_fast8_t srflx_pending_count;
    uint_fast8_t relay_pending_count;
    struct stun_keepalive* stun_keepalive;
};

enum rawrtc_code rawrtc_candidate_helper_create(
    struct rawrtc_candidate_helper** const candidate_helperp, // de-referenced
    struct rawrtc_ice_gatherer* gatherer,
    struct ice_lcand* const candidate,
    udp_helper_recv_h* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_candidate_helper_set_receive_handler(
    struct rawrtc_candidate_helper* const candidate_helper,
    udp_helper_recv_h* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_candidate_helper_find(
    struct rawrtc_candidate_helper** const candidate_helperp,
    struct list* const candidate_helpers,
    struct ice_lcand* re_candidate
);
