#include <string.h> // memset
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <usrsctp.h> // usrsctp*
#include <anyrtc.h>
#include "message_buffer.h"
#include "dtls_transport.h"
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// TODO: This should probably be in usrsctp.h
#define SCTP_EVENT_READ    0x0001
#define SCTP_EVENT_WRITE   0x0002
#define SCTP_EVENT_ERROR   0x0004

volatile int wat = 0; // TODO: Look, I know this is stupid, but it's going to be removed anyway

//
/*
 * Handle outgoing SCTP messages.
 */
static int sctp_packet_handler(
        void* arg,
        void* buffer,
        size_t length,
        uint8_t tos,
        uint8_t set_df
) {
    struct anyrtc_sctp_transport* const transport = arg;

    // TODO: Can an upcall/output trigger an upcall/output? This COULD result in a deadlock.
    if (wat) {
        printf("mutex locked twice, PANIC?!\n");
    }

    // Lock event loop mutex
    re_thread_enter();
    ++wat; // TODO: Remove
    DEBUG_PRINTF("No deadlock\n"); // TODO: Remove

    // TODO: Send on DTLS transport
    DEBUG_WARNING("TODO: HANDLE OUTGOING SCTP PACKET\n");

out:
    // Unlock event loop mutex
    re_thread_leave();
    --wat; // TODO: Remove

    // TODO: What does the return code do?
    return 0;
}

/*
 * Handle usrsctp events.
 */
static void upcall_handler(
        struct socket* sock,
        void* arg,
        int flags
) {
    struct anyrtc_sctp_transport* const transport = arg;
    int events = usrsctp_get_events(sock);

    // TODO: Can an upcall/output trigger an upcall/output? This COULD result in a deadlock.
    if (wat) {
        printf("mutex locked twice, PANIC?!\n");
    }

    // Lock event loop mutex
    re_thread_enter();
    ++wat; // TODO: Remove
    DEBUG_PRINTF("No deadlock\n"); // TODO: Remove

    // Closed?
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring SCTP event, transport is closed\n");
        goto out;
    }

    // Error?
    if (events & SCTP_EVENT_ERROR) {
        // TODO: What am I supposed to do with this information?
        DEBUG_WARNING("SCTP error event\n");
    }

    // Can read?
    if (events & SCTP_EVENT_READ) {
        DEBUG_WARNING("TODO: CAN READ\n");
//        struct mbuf* buffer;
//        ssize_t length;
//        struct sockaddr_in source;
//        socklen_t source_length = sizeof(struct sockaddr_in);
//        struct sctp_nxtinfo info = {0};
//        socklen_t info_length = sizeof(struct sctp_recvv_rn);
//        unsigned int info_type = SCTP_RECVV_NOINFO;
//        int recv_flags = 0;
//
//        // TODO: Get datagram size
//        length = ???;
//
//        // Create buffer (when buffering)
//        // OR increase size of buffer if needed
//
//        // TODO: Do we need to do anything with info? Or can we NULL it if we don't use it?
//        length = usrsctp_recvv(
//                sock, buffer->buf, buffer->size, (struct sockaddr*) &source, &source_length,
//                &info, &info_length, &info_type, &recv_flags);
//        if (length == -1) {
//            DEBUG_WARNING("SCTP receive failed, reason: %m\n", errno);
//            // TODO: What now?
//            goto out;
//        }
//
//        // Handle (if receive handler exists)
//        if (transport->receive_handler) {
//            transport->receive_handler(buffer, transport->receive_handler_arg);
//            goto out;
//        }
//
//        // Buffer message
//        enum anyrtc_code error = anyrtc_message_buffer_append(
//                &transport->buffered_messages, NULL, buffer);
//        if (error) {
//            DEBUG_WARNING("Could not buffer SCTP packet, reason: %s\n", anyrtc_code_to_str(error));
//        } else {
//            DEBUG_PRINTF("Buffered SCTP packet of size %zu\n", mbuf_get_left(buffer));
//        }
    }

    // Can write?
    // TODO: How often is this called? What does 'write' tell me?
    if (events & SCTP_EVENT_WRITE) {
        DEBUG_WARNING("TODO: CAN WRITE\n");
    }

out:
    // Unlock event loop mutex
    re_thread_leave();
    --wat; // TODO: Remove
}

/*
 * Handle incoming SCTP messages.
 */
static void dtls_receive_handler(
        struct mbuf* const buffer,
        void* const arg
) {
    struct anyrtc_sctp_transport* const transport = arg;
    size_t const length = mbuf_get_left(buffer);

    // Closed?
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring incoming SCTP message, transport is closed\n");
        return;
    }

    // Feed into SCTP socket
    // TODO: What about ECN bits?
    DEBUG_PRINTF("Feeding SCTP packet of %zu bytes\n", length);
    usrsctp_conninput(transport->socket, mbuf_buf(buffer), length, 0);
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
    struct sockaddr_conn peer = {0};
    enum anyrtc_code error;

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
    // TODO: Call this once (?)
    usrsctp_init(0, sctp_packet_handler, dbg_info);

    // TODO: Debugging depending on options
#ifdef SCTP_DEBUG
    usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

    // TODO: What does this do?
    usrsctp_sysctl_set_sctp_blackhole(2);

    // TODO: Do we need this?
    //usrsctp_register_address(...);

    // Create SCTP socket
    // TODO: Do we need a send handler? What does 'threshold' do?
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, transport);
    if (!socket) {
        DEBUG_WARNING("Could not create socket, reason: %m\n", errno);
        goto out;
    }

    // Make socket non-blocking
    if (usrsctp_set_non_blocking(transport->socket, 1)) {
        DEBUG_WARNING("Could not set to non-blocking, reason: %m\n", errno);
        goto out;
    }

    // Set event callback
    if (usrsctp_set_upcall(transport->socket, upcall_handler, transport)) {
        DEBUG_WARNING("Could not set event callback (upcall), reason: %m\n", errno);
        goto out;
    }

    // Set peer address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    // sconn.sconn_len = sizeof(struct sockaddr_conn);
    peer.sconn_port = port;
    // Note: This is a hack to get our transport instance in the send handler
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
        if (transport->socket) {
            usrsctp_close(transport->socket);
        }
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

