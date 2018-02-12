#pragma once

#define RAWRTC_PEER_CONNECTION_DESCRIPTION_MID "rawrtc-sctp-dc"

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
