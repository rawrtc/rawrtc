#include <netinet/in.h> // htons, ...
#include <string.h> // strlen, memcpy
#include <usrsctp.h> // SCTP_RECVV_RCVINFO, ...
#include <anyrtc.h>
#include "sctp_data_channel.h"

#define DEBUG_MODULE "sctp-data-channel"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Initiating peer:
 * - Select SID (dtls role server: odd, dtls role client: even)
 * - Send DATA_CHANNEL_OPEN on outgoing SID (reliable and ordered)
 * - Can directly send data before ACK received
 * Responding peer:
 * - Check SID (?)
 * - Send DATA_CHANNEL_ACK on outgoing SID (reliable and ordered)
 * After ack:
 * - DC open
 * - reliability settings must be set with each message
 *
 * anyrtc_data_channel_create
 * + transport->data_channel_create_handler(channel, parameters, transport)
 *   + sctp_transport find free sid or fail, channels[sid] = channel
 *     + data_channel_open_message_send(channel, parameters, transport, sid)
 *       + anyrtc_sctp_transport_send(transport, ...)
 *
 * anyrtc_data_channel_close
 * + transport->data_channel_close_handler(channel)
 *   + sctp_transport:
 *     + channel
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
 * Create a data channel open message.
 */
static enum anyrtc_code data_channel_open_message_create(
        struct data_channel_open** const messagep, // de-referenced
        struct anyrtc_data_channel_parameters* const parameters
) {
    size_t const label_length = strlen(parameters->label);
    size_t const protocol_length = strlen(parameters->protocol);
    struct data_channel_open* message;

    // Check string length
    if (label_length > UINT16_MAX || protocol_length > UINT16_MAX) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    // TODO: Once we can use vectored send in usrsctp, we can use an iov for the strings and
    // do not need to allocate the struct
    // https://github.com/nplab/dctt/blob/bcff62eeb53fa02f5d5da9fe145ce7cafa1a3780/dctt.c#L201
    message = mem_alloc(sizeof(*message) + label_length + protocol_length, NULL);
    if (!message) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    message->message_type = ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_TYPE_OPEN;
    message->channel_type = parameters->channel_type;
    message->priority = htons(ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_PRIORITY_NORMAL); // TODO: Ok?
    message->reliability_parameter = htonl(parameters->reliability_parameter);
    message->label_length = htons((uint16_t) label_length);
    message->protocol_length = htons((uint16_t) protocol_length);
    memcpy(message->label_and_protocol, parameters->label, label_length);
    memcpy(message->label_and_protocol + label_length, parameters->protocol, protocol_length);

    // Set pointer & done
    *messagep = message;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Create a data channel ack message.
 */
static void data_channel_ack_message(
        struct data_channel_ack* const message // modified
) {
    // Set fields
    message->message_type = ANYRTC_SCTP_DATA_CHANNEL_MESSAGE_TYPE_ACK;
}

/*
 * SCTP data channel create handler.
 */
static enum anyrtc_code anyrtc_sctp_data_channel_open(
        struct anyrtc_data_channel* const channel,
        struct anyrtc_data_transport* const transport,
        struct anyrtc_data_channel_parameters* const parameters
) {
    // Create data channel open message
    return ANYRTC_CODE_NOT_IMPLEMENTED; // TODO: Implement
}

/*
 * Handle incoming SCTP message.
 * TODO: Map to SCTP data channel
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
