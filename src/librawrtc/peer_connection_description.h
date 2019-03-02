#pragma once
#include <rawrtc.h>

#define RAWRTC_PEER_CONNECTION_DESCRIPTION_MID "rawrtc-sctp-dc"

struct rawrtc_peer_connection_description {
    struct rawrtc_peer_connection* connection;
    enum rawrtc_sdp_type type;
    bool trickle_ice;
    char* bundled_mids;
    char* remote_media_line;
    uint8_t media_line_index;
    char* mid;
    bool sctp_sdp_05;
    bool end_of_candidates;
    struct list ice_candidates;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct rawrtc_sctp_capabilities* sctp_capabilities;
    uint16_t sctp_port;
    struct mbuf* sdp;
};

enum {
    RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SIZE = 1024,
    RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_MAX_MESSAGE_SIZE = 65536,
    RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SCTP_PORT = 5000
};

enum rawrtc_code rawrtc_peer_connection_description_create_internal(
    struct rawrtc_peer_connection_description** const descriptionp,
    struct rawrtc_peer_connection* const connection,
    bool const offering
);

enum rawrtc_code rawrtc_peer_connection_description_add_candidate(
    struct rawrtc_peer_connection_description* const description,
    struct rawrtc_peer_connection_ice_candidate* const candidate
);

int rawrtc_peer_connection_description_debug(
    struct re_printf* const pf,
    struct rawrtc_peer_connection_description* const description
);
