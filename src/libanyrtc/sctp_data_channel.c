#include <usrsctp.h> // SCTP_RECVV_RCVINFO, ...
#include <anyrtc.h>
#include "sctp_data_channel.h"

#define DEBUG_MODULE "sctp-data-channel"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Initiating peer:
 * - Select SID (dtls role server: odd, dtls role client: even)
 * - Send DATA_CHANNEL_OPEN on outgoing SID
 * - Can directly send data before ACK received
 * Responding peer:
 * - Check SID (?)
 * - Send DATA_CHANNEL_ACK on outgoing SID
 * After ack:
 * - DC open
 * - reliability settings must be set with each message
 *
 */

struct data_channel_open {
    uint8_t message_type;
    uint8_t channel_type;
    uint16_t priority;
    uint32_t reliability_parameter;
    uint16_t label_length;
    uint16_t protocol_length;
    uint8_t label_and_protocol[];
} __attribute__((packed));

struct data_channel_ack {
    uint8_t message_type;
} __attribute__((packed));


/*
 * Set a data channel open request.
 */
static enum anyrtc_code data_channel_open_request(
        struct data_channel_open* const message, // copied into
        struct anyrtc_data_channel_parameters* const parameters
) {
    message->message_type = ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_TYPE_OPEN;
    message->channel_type = parameters->channel_type;
    message->priority = ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_NORMAL; // TODO: Correct?
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}


/*
 * Handle incoming SCTP message.
 */
enum anyrtc_code anyrtc_sctp_data_channel_receive_handler(
        struct anyrtc_sctp_transport* const transport,
        struct mbuf* const buffer,
        struct sctp_rcvinfo* const info
) {
    info->rcv_ppid = ntohl(info->rcv_ppid);
    DEBUG_INFO("STREAM ID: %"PRIu16", PPID: %"PRIu32"\n", info->rcv_sid, info->rcv_ppid);

    DEBUG_WARNING("TODO: HANDLE MESSAGE\n");
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
