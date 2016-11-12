#include <string.h> // memset, memcpy
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

/*
 * Handle incoming message.
 * TODO: Move into own directory
 */
static void dcep_receive_handler(
        struct mbuf* const buffer,
        void* const arg
) {

}

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
    enum anyrtc_code error;
    (void) tos; // TODO: Handle?
    (void) set_df; // TODO: Handle?

    DEBUG_PRINTF("SCTP_PACKET_HANDLER\n");

    // TODO: Can an upcall/output trigger an upcall/output? This COULD result in a deadlock.
    if (transport->wat) {
        printf("mutex locked twice, PANIC?!\n");
    }

    // Lock event loop mutex
    re_thread_enter();
    ++transport->wat; // TODO: Remove
    DEBUG_PRINTF("No deadlock\n"); // TODO: Remove

    // Note: We only need to copy the buffer if we add it to the outgoing queue
    if (transport->dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        struct mbuf mbuffer;

        // Note: dtls_send does not reference the buffer, so we can safely fake an mbuf structure
        // to avoid copying. This may change in the future, so be aware!
        mbuffer.buf = buffer;
        mbuffer.pos = 0;
        mbuffer.size = length;
        mbuffer.end = length;

        // Send
        error = anyrtc_dtls_transport_send(transport->dtls_transport, &mbuffer);
        if (error) {
            DEBUG_WARNING("Could not send packet, reason: %s\n", anyrtc_code_to_str(error));
            goto out;
        }
    } else {
        // Allocate
        struct mbuf* const mbuffer = mbuf_alloc(length);
        if (!mbuffer) {
            DEBUG_WARNING("Could not create buffer for outgoing packet, no memory\n");
            goto out;
        }

        // Copy and set size/end
        memcpy(mbuffer->buf, buffer, length);
        mbuffer->end = length;

        // Send (well, actually buffer...)
        error = anyrtc_dtls_transport_send(transport->dtls_transport, mbuffer);
        mem_deref(mbuffer);
        if (error) {
            DEBUG_WARNING("Could not send packet, reason: %s\n", anyrtc_code_to_str(error));
            goto out;
        }
    }

out:
    // Unlock event loop mutex
    re_thread_leave();
    --transport->wat; // TODO: Remove

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

    // TODO: Remove
    DEBUG_PRINTF("UPCALL_HANDLER\n");

    // TODO: Can an upcall/output trigger an upcall/output? This COULD result in a deadlock.
    if (transport->wat) {
        printf("mutex locked twice, PANIC?!\n");
    }

    // Lock event loop mutex
    re_thread_enter();
    ++transport->wat; // TODO: Remove
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
        struct mbuf* buffer;
        ssize_t length;
        struct sockaddr_in source;
        socklen_t source_length = sizeof(struct sockaddr_in);
        struct sctp_recvv_rn info;
        socklen_t info_length = 0;
        unsigned int info_type = SCTP_RECVV_NOINFO;
        int recv_flags = MSG_PEEK;

        // Get datagram size
        length = usrsctp_recvv(
                sock, NULL, 0, NULL, 0,
                &info, &info_length, &info_type, &recv_flags);
        if (length == -1) {
            if (recv_flags & MSG_NOTIFICATION) {
                DEBUG_WARNING("Ignoring message notification\n");
                goto out;
            }
            if (info_type == SCTP_RECVV_RN) {
                uint32_t packet_size = info.recvv_nxtinfo.nxt_length;
                DEBUG_INFO("PACKET SIZE: %"PRIu32"\n", packet_size);
            } else {
                DEBUG_WARNING("Unexpected info type\n");
                goto out;
            }
            DEBUG_WARNING("SCTP receive failed, reason: %m\n", errno);
            // TODO: What now?
            goto out;
        }

        DEBUG_WARNING("TODO: NOW WHAT?\n");

        // Create buffer (when buffering)
        // OR increase size of buffer if needed

//        // Receive datagram
//        info_length = 0;
//        info_type = SCTP_RECVV_NOINFO;
//        recv_flags = 0;
//        length = usrsctp_recvv(
//                sock, buffer->buf, buffer->size, (struct sockaddr*) &source, &source_length,
//                NULL, &info_length, &info_type, &recv_flags);
//        if (length == -1) {
//            DEBUG_WARNING("SCTP receive failed, reason: %m\n", errno);
//            // TODO: What now?
//            goto out;
//        }

//        dcep_receive_handler(buffer, NULL);

//        // Handle (if receive handler exists)
//        if (transport->receive_handler) {
//            transport->receive_handler(buffer, transport->receive_handler_arg);
//            goto out;
//        }

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
    --transport->wat; // TODO: Remove
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
    struct sockaddr_in6 local = {0};
    struct sockaddr_conn remote = {0};
    enum anyrtc_code error;
    int option_value;

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



    // Disable ECN
    usrsctp_sysctl_set_sctp_ecn_enable(0);

    // Create SCTP socket
    // TODO: Do we need a send handler? What does 'threshold' do?
    DEBUG_PRINTF("Creating SCTP socket\n");
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
    if (!transport->socket) {
        DEBUG_WARNING("Could not create socket, reason: %m\n", errno);
        goto out;
    }

    // Make socket non-blocking
    if (usrsctp_set_non_blocking(transport->socket, 1)) {
        DEBUG_WARNING("Could not set to non-blocking, reason: %m\n", errno);
        goto out;
    }

    // We want info
    option_value = 1;
    if (usrsctp_setsockopt(
            transport->socket, IPPROTO_SCTP, SCTP_RECVNXTINFO,
            &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not set socket option, reason: %m\n", errno);
    }

    // Set event callback
    if (usrsctp_set_upcall(transport->socket, upcall_handler, transport)) {
        DEBUG_WARNING("Could not set event callback (upcall), reason: %m\n", errno);
        goto out;
    }

    // Bind local address
    // TODO: Check for existance of sin6_len
    //local.sin6_len = sizeof(struct sockaddr_in6);
    local.sin6_family = AF_INET6;
    local.sin6_addr = in6addr_any;
    local.sin6_port = htons(port);
    if (usrsctp_bind(transport->socket, (struct sockaddr*) &local, sizeof(struct sockaddr_in6))) {
        DEBUG_WARNING("Could not bind local address, reason: %m\n", errno);
        goto out;
    }

    // Set remote address
    remote.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(struct sockaddr_conn);
    // TODO: This is incorrect. Furthermore, we don't actually know which port we have to choose.
    // TODO: Open an issue about that on ORTC spec.
    remote.sconn_port = htons(port);
    // Note: This is a hack to get our transport instance in the send handler
    remote.sconn_addr = transport;

    // Attach to ICE transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = anyrtc_dtls_transport_set_data_transport(dtls_transport, dtls_receive_handler, transport);
    if (error) {
        goto out;
    }

    // Connect
    DEBUG_PRINTF("Connecting to remote\n");
    if (usrsctp_connect(transport->socket, (struct sockaddr*) &remote, sizeof(remote))
            && errno != EINPROGRESS) {
        DEBUG_WARNING("Could not connect, reason: %m\n", errno);
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

