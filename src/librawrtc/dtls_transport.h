#pragma once

enum rawrtc_code rawrtc_dtls_transport_create_internal(
    struct rawrtc_dtls_transport** const transportp, // de-referenced
    struct rawrtc_ice_transport* const ice_transport, // referenced
    struct list* certificates, // de-referenced, copied (shallow)
    rawrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
    rawrtc_dtls_transport_error_handler* const error_handler, // nullable
    void* const arg // nullable
);

enum rawrtc_code rawrtc_dtls_transport_add_candidate_pair(
    struct rawrtc_dtls_transport* const transport,
    struct ice_candpair* const candidate_pair
);

enum rawrtc_code rawrtc_dtls_transport_have_data_transport(
    bool* const have_data_transportp, // de-referenced
    struct rawrtc_dtls_transport* const transport
);

enum rawrtc_code rawrtc_dtls_transport_set_data_transport(
    struct rawrtc_dtls_transport* const transport,
    rawrtc_dtls_transport_receive_handler* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_dtls_transport_clear_data_transport(
    struct rawrtc_dtls_transport* const transport
);

enum rawrtc_code rawrtc_dtls_transport_send(
    struct rawrtc_dtls_transport* const transport,
    struct mbuf* const buffer
);
