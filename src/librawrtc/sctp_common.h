#pragma once
#include <rawrtc.h>

enum rawrtc_code rawrtc_sctp_common_dtls_role_getter(
    enum rawrtc_external_dtls_role* const rolep, // de-referenced, not checked
    void* const arg // not checked
);

enum rawrtc_code rawrtc_sctp_common_dtls_transport_state_getter(
    enum rawrtc_external_dtls_transport_state* const statep, // de-referenced, not checked
    void* const arg // not checked
);

enum rawrtc_code rawrtc_sctp_common_sctp_transport_outbound_handler(
    struct mbuf* const buffer, // not checked
    uint8_t const tos,
    uint8_t const set_df,
    void* const arg // not checked
);

void rawrtc_sctp_common_sctp_transport_detach_handler(
    void* const arg // not checked
);
