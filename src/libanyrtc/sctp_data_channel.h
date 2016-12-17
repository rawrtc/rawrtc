#pragma once

/*
 * Data channel SCTP payload protocol identifier.
 */
enum anyrtc_sctp_data_channel_ppid {
    ANYRTC_SCTP_DATA_CHANNEL_PPID_CONTROL = 50,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_DOMSTRING = 51,
    ANYRTC_SCTP_DATA_CHANNEL_PPID_BINARY = 52
};

enum anyrtc_code anyrtc_sctp_data_channel_receive_handler(
    struct anyrtc_sctp_transport* const transport,
    struct mbuf* const buffer,
    struct sctp_rcvinfo* const info
);
