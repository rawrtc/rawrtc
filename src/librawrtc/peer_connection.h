#pragma once
#include <rawrtc.h>

enum {
    RAWRTC_PEER_CONNECTION_SCTP_TRANSPORT_PORT = 5000
};

/*
 * Peer connection context.
 */
struct rawrtc_peer_connection_context {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* ice_gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct list certificates;
    char dtls_id[DTLS_ID_LENGTH + 1];
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_data_transport* data_transport;
};

struct rawrtc_peer_connection {
    enum rawrtc_peer_connection_state connection_state;
    enum rawrtc_signaling_state signaling_state;
    struct rawrtc_peer_connection_configuration* configuration; // referenced
    rawrtc_negotiation_needed_handler* negotiation_needed_handler; // nullable
    rawrtc_peer_connection_local_candidate_handler* local_candidate_handler; // nullable
    rawrtc_peer_connection_local_candidate_error_handler* local_candidate_error_handler; // nullable
    rawrtc_signaling_state_change_handler* signaling_state_change_handler; // nullable
    rawrtc_ice_transport_state_change_handler* ice_connection_state_change_handler; // nullable
    rawrtc_ice_gatherer_state_change_handler* ice_gathering_state_change_handler; // nullable
    rawrtc_peer_connection_state_change_handler* connection_state_change_handler; // nullable
    rawrtc_data_channel_handler* data_channel_handler; // nullable
    enum rawrtc_data_transport_type data_transport_type;
    struct rawrtc_peer_connection_description* local_description; // referenced
    struct rawrtc_peer_connection_description* remote_description; // referenced
    struct rawrtc_peer_connection_context context;
    void* arg; // nullable
};
