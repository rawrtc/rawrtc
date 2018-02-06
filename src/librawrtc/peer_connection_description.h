#pragma once

#define RAWRTC_PEER_CONNECTION_DESCRIPTION_MID "rawrtc-sctp-dc"

enum {
    RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SIZE = 1024,
};

enum rawrtc_code rawrtc_peer_connection_description_create_internal(
    struct rawrtc_peer_connection_description** const descriptionp,
    struct rawrtc_peer_connection* const connection,
    bool const offerer
);
