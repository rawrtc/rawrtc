#pragma once

enum {
    RAWRTC_SCTP_TRANSPORT_TIMER_TIMEOUT = 10, // TODO: @ruengeler why 10ms?
    RAWRTC_SCTP_TRANSPORT_DEFAULT_PORT = 5000,
    // TODO: Suggest re-adding reconfiguration of number of streams to spec
    // because this requires too many streams to allocate who eat up memory
    // Maybe add a configuration entry to enable/disable 'strict' mode
    RAWRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS = 65535,
    RAWRTC_SCTP_TRANSPORT_MAX_MESSAGE_SIZE = 0,
    RAWRTC_SCTP_TRANSPORT_SID_MAX = 65534,
    RAWRTC_SCTP_TRANSPORT_EMPTY_MESSAGE_SIZE = 1
};

/*
 * DCEP message types.
 */
enum {
    RAWRTC_DCEP_MESSAGE_TYPE_ACK = 0x02,
    RAWRTC_DCEP_MESSAGE_TYPE_OPEN = 0x03
};

/*
 * DCEP message sizes
 */
enum {
    RAWRTC_DCEP_MESSAGE_ACK_BASE_SIZE = 1,
    RAWRTC_DCEP_MESSAGE_OPEN_BASE_SIZE = 12,
};

/*
 * DCEP message priorities.
 */
enum {
    RAWRTC_DCEP_CHANNEL_PRIORITY_LOW = 128,
    RAWRTC_DCEP_CHANNEL_PRIORITY_NORMAL = 256,
    RAWRTC_DCEP_CHANNEL_PRIORITY_HIGH = 512,
    RAWRTC_DCEP_CHANNEL_PRIORITY_EXTRA_HIGH = 1024
};

/*
 * DCEP payload protocol identifiers.
 */
enum {
    RAWRTC_SCTP_TRANSPORT_PPID_DCEP = 50,
    RAWRTC_SCTP_TRANSPORT_PPID_UTF16 = 51,
    RAWRTC_SCTP_TRANSPORT_PPID_UTF16_EMPTY = 56,
    RAWRTC_SCTP_TRANSPORT_PPID_UTF16_PARTIAL = 54, // deprecated
    RAWRTC_SCTP_TRANSPORT_PPID_BINARY = 53,
    RAWRTC_SCTP_TRANSPORT_PPID_BINARY_EMPTY = 57,
    RAWRTC_SCTP_TRANSPORT_PPID_BINARY_PARTIAL = 52 // deprecated
};

enum rawrtc_code rawrtc_sctp_transport_send(
    struct rawrtc_sctp_transport* const transport,
    struct mbuf* const buffer,
    void* const info,
    socklen_t const info_size,
    unsigned int const info_type,
    int const flags
);
