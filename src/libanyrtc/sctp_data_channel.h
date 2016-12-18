#pragma once

/*
 * Data channel SCTP message types.
 */
enum {
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_TYPE_ACK = 0x02,
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_TYPE_OPEN = 0x03,
};

/*
 * Data channel SCTP message priorities.
 */
enum {
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_LOW = 128,
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_NORMAL = 256,
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_HIGH = 512,
    ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_EXTRA_HIGH = 1024
};

/*
 * Data channel SCTP payload protocol identifiers.
 */
enum {
    ANYRTC_SCTP_DATA_CHANNEL_PPID_CONTROL = 50,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_UTF16 = 51,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_UTF16_EMPTY = 56,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_UTF16_PARTIAL = 54, // deprecated
    ANYRTC_SCTP_DATA_CHANNEL_PPID_BINARY = 53,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_BINARY_EMPTY = 57,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_BINARY_PARTIAL = 52 // deprecated
};

enum anyrtc_code anyrtc_sctp_data_channel_receive_handler(
    struct anyrtc_sctp_transport* const transport,
    struct mbuf* const buffer,
    struct sctp_rcvinfo* const info
);
