#include <string.h> // memset
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <usrsctp.h> // usrsctp*
#include <anyrtc.h>
#include "dtls_transport.h"
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Handle incoming data messages.
 */
static int sctp_receive_handler(
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

/*
 * Handle outgoing SCTP messages.
 */
static int dtls_send_handler(
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
 * Handle incoming SCTP messages.
 */
static void dtls_receive_handler(
        struct mbuf* const buffer,
        void* const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;

    // TODO: Handle
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_sctp_transport_destroy(
        void* const arg
) {
    struct anyrtc_sctp_transport* const transport = arg;

    // Remove from DTLS transport
    // Note: No NULL checking needed as the function will do that for us
    anyrtc_dtls_transport_clear_data_transport(transport->dtls_transport);

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
    bool have_data_transport;
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

    // Check if a data transport is already registered
    error = anyrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
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
    usrsctp_init(0, dtls_send_handler, dbg_info);

    // TODO: What does this do?
    usrsctp_sysctl_set_sctp_blackhole(2);

    // Create SCTP socket
    // TODO: Do we need a send handler? What does 'threshold' do?
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, sctp_receive_handler, NULL, 0, transport);
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
    error = anyrtc_dtls_transport_set_data_transport(dtls_transport, dtls_receive_handler, transport);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

