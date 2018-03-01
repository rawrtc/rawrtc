#pragma once
#include <rawrtc.h>

struct rawrtc_ice_transport {
    enum rawrtc_ice_transport_state state;
    struct rawrtc_ice_gatherer* gatherer; // referenced
    rawrtc_ice_transport_state_change_handler* state_change_handler; // nullable
    rawrtc_ice_transport_candidate_pair_change_handler* candidate_pair_change_handler; // nullable
    void* arg; // nullable
    struct rawrtc_ice_parameters* remote_parameters; // referenced
    struct rawrtc_dtls_transport* dtls_transport; // referenced, nullable
};

enum ice_role rawrtc_ice_role_to_re_ice_role(
    enum rawrtc_ice_role const role
);

enum rawrtc_code rawrtc_re_ice_role_to_ice_role(
    enum rawrtc_ice_role* const rolep, // de-referenced
    enum ice_role const re_role
);
