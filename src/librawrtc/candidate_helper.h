#pragma once
#include <rawrtc.h>
#include "packet_trace.h"

/*
 * STUN keep-alive session.
 */
struct rawrtc_candidate_helper_stun_session {
    struct le le;
    struct rawrtc_candidate_helper* candidate_helper;
    struct ice_lcand* candidate;
    struct stun_keepalive* stun_keepalive;
    struct rawrtc_ice_server_url* url;
};

/*
 * TURN client session.
 */
struct rawrtc_candidate_helper_turn_session {
    struct le le;
    struct rawrtc_candidate_helper* candidate_helper;
    struct ice_lcand* candidate;
    struct turnc* turn_client;
    struct rawrtc_ice_server_url* url;
};

/*
 * Local candidate helper.
 */
struct rawrtc_candidate_helper {
    struct le le;
    struct rawrtc_ice_gatherer* gatherer;
    struct ice_lcand* candidate;
    struct udp_helper* udp_helper;
    struct list trace_packet_helper_contexts;
    struct udp_helper* udp_helper_trace_ice;
    uint_fast8_t srflx_pending_count;
    struct list stun_sessions;
    struct udp_helper* udp_helper_trace_stun;
    uint_fast8_t relay_pending_count;
    struct list turn_sessions;
    struct udp_helper* udp_helper_trace_turn;
};

enum rawrtc_code rawrtc_candidate_helper_create(
    struct rawrtc_candidate_helper** const candidate_helperp, // de-referenced
    struct rawrtc_ice_gatherer* gatherer,
    struct ice_lcand* const re_candidate,
    udp_helper_recv_h* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_candidate_helper_set_receive_handler(
    struct rawrtc_candidate_helper* const candidate_helper,
    udp_helper_recv_h* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_candidate_helper_attach_packet_trace_handler(
    struct udp_helper** const udp_helperp, // de-referenced
    struct rawrtc_candidate_helper* const candidate_helper,
    FILE* const trace_handle,
    enum rawrtc_layer const trace_layer
);

enum rawrtc_code rawrtc_candidate_helper_find(
    struct rawrtc_candidate_helper** const candidate_helperp,
    struct list* const candidate_helpers,
    struct ice_lcand* re_candidate
);

enum rawrtc_code rawrtc_candidate_helper_stun_session_create(
    struct rawrtc_candidate_helper_stun_session** const sessionp, // de-referenced
    struct rawrtc_ice_server_url* const url
);

enum rawrtc_code rawrtc_candidate_helper_stun_session_add(
    struct rawrtc_candidate_helper_stun_session* const session,
    struct rawrtc_candidate_helper* const candidate_helper,
    struct stun_keepalive* const stun_keepalive
);

enum rawrtc_code rawrtc_candidate_helper_stun_session_add_candidate(
    struct rawrtc_candidate_helper_stun_session* const session,
    struct ice_lcand* const re_candidate
);

enum rawrtc_code rawrtc_candidate_helper_turn_session_create(
    struct rawrtc_candidate_helper_turn_session** const sessionp, // de-referenced
    struct rawrtc_ice_server_url* const url
);

enum rawrtc_code rawrtc_candidate_helper_turn_session_add(
    struct rawrtc_candidate_helper_turn_session* const session,
    struct rawrtc_candidate_helper* const candidate_helper,
    struct turnc* const turn_client
);

enum rawrtc_code rawrtc_candidate_helper_turn_session_add_candidate(
    struct rawrtc_candidate_helper_turn_session* const session,
    struct ice_lcand* const re_candidate
);

enum rawrtc_code rawrtc_candidate_helper_remove_sessions(
    struct list* const local_candidates
);

int rawrtc_candidate_helper_debug(
    struct re_printf* const pf,
    struct rawrtc_candidate_helper const* const candidate_helper
);
