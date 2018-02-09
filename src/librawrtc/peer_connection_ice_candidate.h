#pragma once

enum {
    RAWRTC_PEER_CONNECTION_CANDIDATE_DEFAULT_SIZE = 256,
};

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
