#include <string.h> // memset
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <usrsctp.h> // usrsctp*
#include <anyrtc.h>
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

static int receive_handler(
        struct socket* const socket,
        union sctp_sockstore address,
        void* const data,
        size_t length,
        struct sctp_rcvinfo receive_info,
        int flags,
        void* arg
) {
    struct anyrtc_sctp_transport* const transport = arg;

    DEBUG_WARNING("TODO: HANDLE INCOMING SCTP PACKET\n");

    // TODO: What does the return code do?
    return 1;
}

static int send_handler(
        void* const arg,
        void* const buffer,
        size_t length,
        uint8_t tos,
        uint8_t set_df
) {
    struct anyrtc_sctp_transport* const transport = arg;

    DEBUG_WARNING("TODO: HANDLE OUTGOING SCTP PACKET\n");

    // TODO: What does the return code do?
    return 0;
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_sctp_transport_destroy(
        void* const arg
) {
    struct anyrtc_sctp_transport* const transport = arg;

    // Remove from DTLS transport
    if (transport->dtls_transport) {
        transport->dtls_transport->sctp_transport = NULL;
    }

    // TODO: Close usrsctp socket

    // Dereference
    mem_deref(transport->dtls_transport);
}

/*
 * Create an SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_create(
        struct anyrtc_sctp_transport** const transportp, // de-referenced
        struct anyrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t port, // zeroable
        anyrtc_sctp_transport_data_channel_handler* const data_channel_handler, // nullable
        void* const arg // nullable
) {
    struct anyrtc_sctp_transport* transport;
    struct sockaddr_conn peer;
    enum anyrtc_code error = ANYRTC_CODE_UNKNOWN_ERROR;

    // Check arguments
    if (!transportp || !dtls_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check DTLS transport state
    if (dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED
            || dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_FAILED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Check if another SCTP transport is associated to the DTLS transport
    if (dtls_transport->sctp_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(struct anyrtc_dtls_transport),
                           anyrtc_sctp_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = ANYRTC_SCTP_TRANSPORT_STATE_NEW;
    transport->dtls_transport = mem_ref(dtls_transport);
    transport->data_channel_handler = data_channel_handler;
    transport->arg = arg;

    // Set default port (if 0)
    if (port == 0) {
        port = ANYRTC_SCTP_TRANSPORT_DEFAULT_PORT;
    }

    // Initialise usrsctp
    usrsctp_init(0, send_handler, dbg_info);

    // TODO: What does this do?
    usrsctp_sysctl_set_sctp_blackhole(2);

    // Create SCTP socket
    // TODO: Do we need a send handler? What does 'threshold' do?
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, receive_handler, NULL, 0, transport);
    if (!socket) {
        DEBUG_WARNING("SCTP transport could not create socket, reason: %m\n", errno);
        goto out;
    }

    // Make socket non-blocking
    if (usrsctp_set_non_blocking(transport->socket, 1)) {
        DEBUG_WARNING("SCTP transport could not set to non-blocking, reason: %m\n", errno);
        goto out;
    }

    // Set peer address
    memset(&peer, 0, sizeof(peer));
    peer.sconn_family = AF_CONN;
    peer.sconn_port = port;
    // Note: This is a very nasty hack to get our transport instance in the send handler
    peer.sconn_addr = transport;

    // Connect
    if (usrsctp_connect(transport->socket, (struct sockaddr*) &peer, sizeof(peer))) {
        DEBUG_WARNING("SCTP transport could not connect, reason: %m\n", errno);
        goto out;
    }

    // Attach to ICE transport
    // Note: We cannot reference ourselves here as that would introduce a cyclic reference
    dtls_transport->sctp_transport = transport;
    error = ANYRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

