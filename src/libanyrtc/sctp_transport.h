#pragma once

enum {
    ANYRTC_SCTP_TRANSPORT_DEFAULT_BUFFER = 65536,
    ANYRTC_SCTP_TRANSPORT_DEFAULT_PORT = 5000,
    ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS = 65535,
    ANYRTC_SCTP_TRANSPORT_PPID_DCEP = 0x32,
};

enum anyrtc_code anyrtc_sctp_transport_send(
    struct anyrtc_sctp_transport* const transport,
    struct mbuf* const buffer
);
