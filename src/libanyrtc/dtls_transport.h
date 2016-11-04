#pragma once

enum anyrtc_code anyrtc_dtls_transport_add_candidate_pair(
    struct anyrtc_dtls_transport* const transport,
    struct ice_candpair* const candidate_pair
);

enum anyrtc_code anyrtc_dtls_transport_have_data_transport(
    bool* const have_data_transportp, // de-referenced
    struct anyrtc_dtls_transport* const transport
);

enum anyrtc_code anyrtc_dtls_transport_set_data_transport(
    struct anyrtc_dtls_transport* const transport,
    anyrtc_dtls_transport_receive_handler* const receive_handler,
    void* const arg
);

enum anyrtc_code anyrtc_dtls_transport_clear_data_transport(
    struct anyrtc_dtls_transport* const transport
);

enum anyrtc_code anyrtc_dtls_transport_send(
    struct anyrtc_dtls_transport* const transport,
    struct mbuf* const buffer
);
