#pragma once
#include <rawrtc/dtls_transport.h>
#include <rawrtc/ice_gatherer.h>
#include <rawrtc/ice_parameters.h>
#include <rawrtc/ice_transport.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <rew.h>

struct rawrtc_ice_transport {
    enum rawrtc_ice_transport_state state;
    struct rawrtc_ice_gatherer* gatherer;  // referenced
    rawrtc_ice_transport_state_change_handler state_change_handler;  // nullable
    rawrtc_ice_transport_candidate_pair_change_handler candidate_pair_change_handler;  // nullable
    void* arg;  // nullable
    struct list mdns_resolvers;
    struct stun* stun_client;
    struct dnsc* mdns_client;
    struct rawrtc_ice_parameters* remote_parameters;  // referenced
    struct rawrtc_dtls_transport* dtls_transport;  // referenced, nullable
    bool remote_end_of_candidates;
};

enum ice_role rawrtc_ice_role_to_re_ice_role(enum rawrtc_ice_role const role);

enum rawrtc_code rawrtc_re_ice_role_to_ice_role(
    enum rawrtc_ice_role* const rolep,  // de-referenced
    enum ice_role const re_role);
