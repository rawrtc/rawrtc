#include <usrsctp.h> // SCTP_RECVV_RCVINFO, ...
#include <anyrtc.h>
#include "sctp_data_channel.h"

#define DEBUG_MODULE "sctp-data-channel"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

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
