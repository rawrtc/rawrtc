#pragma once

enum {
    ANYRTC_SCTP_TRANSPORT_DEFAULT_BUFFER = 65536,
    ANYRTC_SCTP_TRANSPORT_DEFAULT_PORT = 5000,
    // TODO: Suggest re-adding reconfiguration of number of streams to spec
    // because this requires too many streams to allocate who eat up memory
    ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS = 65535,
    ANYRTC_SCTP_TRANSPORT_PPID_DCEP = 0x32,
};

// Note: Cannot be public until it uses fixed size types in signature (stdint)
enum anyrtc_code anyrtc_sctp_transport_send(
    struct anyrtc_sctp_transport* const transport,
    struct mbuf* const buffer,
    void* const info,
    socklen_t const info_size,
    unsigned int const info_type,
    int const flags
);
