#pragma once
#include <rawrtc.h>

/*
 * usrsctp event flag extensions for handlers.
 */
#define RAWRTC_SCTP_EVENT_NONE (0)
#define RAWRTC_SCTP_EVENT_ALL (SCTP_EVENT_READ | SCTP_EVENT_WRITE | SCTP_EVENT_ERROR)

enum {
    RAWRTC_SCTP_TRANSPORT_TIMER_TIMEOUT = 10,
    RAWRTC_SCTP_TRANSPORT_DEFAULT_PORT = 5000,
    RAWRTC_SCTP_TRANSPORT_NUMBER_OF_STREAMS = 65535,
    RAWRTC_SCTP_TRANSPORT_SID_MAX = 65534,
    RAWRTC_SCTP_TRANSPORT_EMPTY_MESSAGE_SIZE = 1
};

/*
 * SCTP transport flags.
 */
enum {
    RAWRTC_SCTP_TRANSPORT_FLAGS_SENDING_IN_PROGRESS = 1 << 0,
    RAWRTC_SCTP_TRANSPORT_FLAGS_BUFFERED_AMOUNT_LOW = 1 << 1
};

/*
 * SCTP data channel flags.
 */
enum {
    RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED = 1 << 0,
    RAWRTC_SCTP_DATA_CHANNEL_FLAGS_PENDING_STREAM_RESET = 1 << 1,
    RAWRTC_SCTP_DATA_CHANNEL_FLAGS_INCOMING_STREAM_RESET = 1 << 2,
    RAWRTC_SCTP_DATA_CHANNEL_FLAGS_OUTGOING_STREAM_RESET = 1 << 3
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
