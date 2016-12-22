#pragma once

enum {
    ANYRTC_SCTP_TRANSPORT_DEFAULT_BUFFER = 65536,
    ANYRTC_SCTP_TRANSPORT_DEFAULT_PORT = 5000,
    // TODO: Suggest re-adding reconfiguration of number of streams to spec
    // because this requires too many streams to allocate who eat up memory
    // Maybe add a configuration entry to enable/disable 'strict' mode
    ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS = 65535,
    ANYRTC_SCTP_TRANSPORT_MAX_MESSAGE_SIZE = 0,
    ANYRTC_SCTP_TRANSPORT_SID_MAX = 65534
};

/*
 * DCEP message types.
 */
enum {
    ANYRTC_DCEP_MESSAGE_TYPE_ACK = 0x02,
    ANYRTC_DCEP_MESSAGE_TYPE_OPEN = 0x03
};

/*
 * DCEP message sizes
 */
enum {
    ANYRTC_DCEP_MESSAGE_ACK_BASE_SIZE = 1,
    ANYRTC_DCEP_MESSAGE_OPEN_BASE_SIZE = 12
};

/*
 * DCEP message priorities.
 */
enum {
    ANYRTC_DCEP_CHANNEL_PRIORITY_LOW = 128,
    ANYRTC_DCEP_CHANNEL_PRIORITY_NORMAL = 256,
    ANYRTC_DCEP_CHANNEL_PRIORITY_HIGH = 512,
    ANYRTC_DCEP_CHANNEL_PRIORITY_EXTRA_HIGH = 1024
};

/*
 * DCEP payload protocol identifiers.
 */
enum {
    ANYRTC_DCEP_PPID_CONTROL = 50,
    ANYRTC_DCEP_PPID_UTF16 = 51,
    ANYRTC_DCEP_PPID_UTF16_EMPTY = 56,
    ANYRTC_DCEP_PPID_UTF16_PARTIAL = 54, // deprecated
    ANYRTC_DCEP_PPID_BINARY = 53,
    ANYRTC_DCEP_PPID_BINARY_EMPTY = 57,
    ANYRTC_DCEP_PPID_BINARY_PARTIAL = 52 // deprecated
};

enum anyrtc_code anyrtc_sctp_transport_send(
    struct anyrtc_sctp_transport* const transport,
    struct mbuf* const buffer,
    void* const info,
    socklen_t const info_size,
    unsigned int const info_type,
    int const flags
);
