#pragma once

enum {
    RAWRTC_ICE_GATHERER_DNS_SERVERS = 10
};

enum rawrtc_code rawrtc_ice_gatherer_add_turn_permissions(
    struct rawrtc_ice_gatherer* const gatherer,
    struct ice_rcand* const remote_candidate
);
