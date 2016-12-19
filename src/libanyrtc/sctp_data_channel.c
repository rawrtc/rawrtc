#include <netinet/in.h> // htons, ...
#include <string.h> // strlen, memcpy
#include <usrsctp.h> // SCTP_RECVV_RCVINFO, ...
#include <anyrtc.h>
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-data-channel"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/* TODO: Remove me!
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

