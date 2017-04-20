#pragma once

enum rawrtc_code rawrtc_peer_connection_description_create(
    struct rawrtc_peer_connection_description** const descriptionp,
    struct rawrtc_peer_connection* const connection
);
