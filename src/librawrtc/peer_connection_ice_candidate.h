#pragma once
#include <rawrtc.h>

enum {
    RAWRTC_PEER_CONNECTION_CANDIDATE_DEFAULT_SIZE = 256,
};

struct rawrtc_peer_connection_ice_candidate {
    struct le le;
    struct rawrtc_ice_candidate* candidate;
    char* mid;
    int16_t media_line_index;
    char* username_fragment;
};

int rawrtc_peer_connection_ice_candidate_debug(
    struct re_printf* const pf,
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

enum rawrtc_code rawrtc_peer_connection_ice_candidate_from_ortc_candidate(
    struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced
    struct rawrtc_ice_candidate* const ortc_candidate,
    char* const mid, // nullable, referenced
    uint8_t const* const media_line_index, // nullable, copied
    char* const username_fragment // nullable, referenced
);

enum rawrtc_code rawrtc_peer_connection_ice_candidate_create_internal(
    struct rawrtc_peer_connection_ice_candidate** const candidatep, // de-referenced
    struct pl* const sdp,
    char* const mid, // nullable
    uint8_t const* const media_line_index, // nullable
    char* const username_fragment
);
