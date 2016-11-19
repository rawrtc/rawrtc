#include <stdio.h> // fopen
#include <string.h> // memset, memcpy
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM, linger
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <usrsctp.h> // usrsctp*
#include <anyrtc.h>
#include "utils.h"
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

// Initialised flag
static bool usrsctp_initialized = false;

// Events to subscribe to
uint16_t const sctp_events[] = {
    SCTP_ASSOC_CHANGE,
    SCTP_PEER_ADDR_CHANGE,
    SCTP_REMOTE_ERROR,
    SCTP_SHUTDOWN_EVENT,
    SCTP_ADAPTATION_INDICATION,
    SCTP_SEND_FAILED_EVENT,
    SCTP_STREAM_RESET_EVENT,
    SCTP_STREAM_CHANGE_EVENT,
    SCTP_SENDER_DRY_EVENT
};
size_t const sctp_events_length = sizeof(sctp_events) / sizeof(sctp_events[0]);

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

    // Closed?
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring SCTP packet ready event, transport is closed\n");
        goto out;
    }

    // Note: We only need to copy the buffer if we add it to the outgoing queue
    if (transport->dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        struct mbuf mbuffer;

        // Note: dtls_send does not reference the buffer, so we can safely fake an mbuf structure
        // to avoid copying. This may change in the future, so be aware!
        mbuffer.buf = buffer;
        mbuffer.pos = 0;
        mbuffer.size = length;
        mbuffer.end = length;

        // Trace (if trace handle)
        // Note: No need to check if NULL as the function does it for us
        anyrtc_trace_packet(transport->trace_handle, &mbuffer);

        // Send
        error = anyrtc_dtls_transport_send(transport->dtls_transport, &mbuffer);
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

        // Trace (if trace handle)
        // Note: No need to check if NULL as the function does it for us
        anyrtc_trace_packet(transport->trace_handle, mbuffer);

        // Send (well, actually buffer...)
        error = anyrtc_dtls_transport_send(transport->dtls_transport, mbuffer);
        mem_deref(mbuffer);
    }

    // Handle error
    if (error) {
        DEBUG_WARNING("Could not send packet, reason: %s\n", anyrtc_code_to_str(error));
        goto out;
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
        DEBUG_PRINTF("Ignoring SCTP upcall event, transport is closed\n");
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
        unsigned int info_type = SCTP_RECVV_RN;
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

    // Trace (if trace handle)
    // Note: No need to check if NULL as the function does it for us
    anyrtc_trace_packet(transport->trace_handle, buffer);

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

    // Close socket and close transport
    usrsctp_close(transport->socket);
    transport->state = ANYRTC_SCTP_TRANSPORT_STATE_CLOSED;
    transport->socket = NULL;

    // Deregister instance
    usrsctp_deregister_address(transport);

    // Close trace file (if any)
    if (transport->trace_handle) {
        if (fclose(transport->trace_handle)) {
            DEBUG_WARNING("Could not close trace file, reason: %m\n", errno);
        }
    }

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
    char trace_handle_id[8];
    char* trace_handle_name;
    struct sctp_assoc_value av;
    struct linger linger_option;
    struct sctp_event sctp_event = {0};
    size_t i;
    struct sctp_initmsg sctp_init_options = {0};
    struct sockaddr_conn peer = {0};
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

    // Initialise usrsctp (if not already initialised)
    if (!usrsctp_initialized) {
        usrsctp_init(0, sctp_packet_handler, dbg_info);

        // TODO: Debugging depending on options
#ifdef SCTP_DEBUG
        usrsctp_sysctl_set_sctp_debug_on(SCTP_DEBUG_ALL);
#endif

        // Do not send ABORTs in response to INITs (1).
        // Do not send ABORTs for received Out of the Blue packets (2).
        usrsctp_sysctl_set_sctp_blackhole(2);

        // Disable the Explicit Congestion Notification extension
        usrsctp_sysctl_set_sctp_ecn_enable(0);

        // Disable the Address Reconfiguration extension
        // TODO: This is still enabled in SCTP INIT for some reason
        usrsctp_sysctl_set_sctp_auto_asconf(0);

        // Disable the Authentication extension
        usrsctp_sysctl_set_sctp_auth_enable(0);

        // Disable the NR-SACK extension
        // TODO: Why?
        usrsctp_sysctl_set_sctp_nrsack_enable(0);

        // Disable the Packet Drop Report extension
        // TODO: Why?
        usrsctp_sysctl_set_sctp_pktdrop_enable(0);

        // Enable the Partial Reliability extension
        // TODO: This is not set in SCTP INIT for some reason
        usrsctp_sysctl_set_sctp_pr_enable(1);

        // Set amount of incoming streams
        // TODO: usrsctp_sysctl_set_sctp_nr_incoming_streams_default is not defined
        //    usrsctp_sysctl_set_sctp_nr_incoming_streams_default(
        //            ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS);

        // Set amount of outgoing streams
        usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(
                ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS);

        // Initialised
        usrsctp_initialized = true;
    }

    // Create packet tracer
    // TODO: Debug mode only, filename set by debug options
    rand_str(trace_handle_id, sizeof(trace_handle_id));
    error = anyrtc_sdprintf(&trace_handle_name, "trace-sctp-%s.hex", trace_handle_id);
    if (error) {
        DEBUG_WARNING("Could create trace file name, reason: %s\n", anyrtc_code_to_str(error));
    } else {
        transport->trace_handle = fopen(trace_handle_name, "w");
        mem_deref(trace_handle_name);
        if (!transport->trace_handle) {
            DEBUG_WARNING("Could not open trace file, reason: %m\n", errno);
        } else {
            DEBUG_INFO("Using trace handle id: %s\n", trace_handle_id);
        }
    }

    // Create SCTP socket
    // TODO: Do we need a send handler? What does 'threshold' do?
    DEBUG_PRINTF("Creating SCTP socket\n");
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
    if (!transport->socket) {
        DEBUG_WARNING("Could not create socket, reason: %m\n", errno);
        goto out;
    }

    // Register instance
    // TODO: Why?
    usrsctp_register_address(transport);

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

    // Enable the Stream Reconfiguration extension
    av.assoc_id = SCTP_ALL_ASSOC;
    av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
                           &av, sizeof(struct sctp_assoc_value))) {
        DEBUG_WARNING("Could not enable stream reconfiguration extension, reason: %m\n", errno);
        goto out;
    }

    // TODO: Set MTU
    // https://github.com/ortclib/ortclib-cpp/blob/master/ortc/cpp/ortc_SCTPTransport.cpp#L2143

    // We want info
    option_value = 1;
    if (usrsctp_setsockopt(
            transport->socket, IPPROTO_SCTP, SCTP_RECVNXTINFO,
            &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not set socket option, reason: %m\n", errno);
        goto out;
    }

    // Discard pending packets when closing
    // TODO: OK?
    linger_option.l_onoff = 1;
    linger_option.l_linger = 0;
    if (usrsctp_setsockopt(transport->socket, SOL_SOCKET, SO_LINGER,
                           &linger_option, sizeof(linger_option))) {
        DEBUG_WARNING("Could not set linger options, reason: %m\n", errno);
        goto out;
    }

    // Set no delay option
    // TODO: Why?
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_NODELAY,
                           &av.assoc_value, sizeof(av.assoc_value))) {
        DEBUG_WARNING("Could not enable stream reconfiguration extension, reason: %m\n", errno);
        goto out;
    }

    // Subscribe to SCTP event notifications
    sctp_event.se_assoc_id = SCTP_ALL_ASSOC;
    sctp_event.se_on = 1;
    for (i = 0; i < sctp_events_length; ++i) {
        sctp_event.se_type = sctp_events[i];
        if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_EVENT,
                               &sctp_event, sizeof(sctp_event))) {
            DEBUG_WARNING("Could not subscribe to event notification, reason: %m", errno);
            goto out;
        }
    }

    // Set number of streams (outgoing and incoming)
    // TODO: Use options?
    sctp_init_options.sinit_num_ostreams = ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS;
    sctp_init_options.sinit_max_instreams = ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS;
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_INITMSG,
                           &sctp_init_options, sizeof(sctp_init_options))) {
        DEBUG_WARNING("Could not set number of streams, reason: %m", errno);
        goto out;
    }

    // Bind local address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(struct sockaddr_conn);
    peer.sconn_port = htons(port);
    // Note: This is a hack to get our transport instance in the send handler
    peer.sconn_addr = transport;
    if (usrsctp_bind(transport->socket, (struct sockaddr*) &peer, sizeof(peer))) {
        DEBUG_WARNING("Could not bind local address, reason: %m\n", errno);
        goto out;
    }

    // Set remote address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(struct sockaddr_conn);
    // TODO: This is incorrect. Furthermore, we don't actually know which port we have to choose.
    // TODO: Open an issue about that on ORTC spec.
    peer.sconn_port = htons(port);
    // Note: This is a hack to get our transport instance in the send handler
    peer.sconn_addr = transport;

    // Attach to ICE transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = anyrtc_dtls_transport_set_data_transport(
            dtls_transport, dtls_receive_handler, transport);
    if (error) {
        goto out;
    }

    // Connect
    DEBUG_PRINTF("Connecting to peer\n");
    if (usrsctp_connect(transport->socket, (struct sockaddr*) &peer, sizeof(peer))
            && errno != EINPROGRESS) {
        DEBUG_WARNING("Could not connect, reason: %m\n", errno);
        goto out;
    }

out:
    if (error) {
        if (transport->socket) {
            usrsctp_deregister_address(transport);
            usrsctp_close(transport->socket);
        }
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

/*
 * Send a data message over the SCTP transport.
 * TODO: Add partial reliability options.
 */
enum anyrtc_code anyrtc_sctp_transport_send(
        struct anyrtc_sctp_transport* const transport,
        struct mbuf* const buffer
) {
    struct sctp_sendv_spa spa = {0};
    ssize_t length;

    // Check arguments
    if (!transport || !buffer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Partial reliability setting
    // TODO
    spa.sendv_sndinfo.snd_sid = 1;
    spa.sendv_sndinfo.snd_flags = SCTP_EOR;
    spa.sendv_sndinfo.snd_ppid = htonl(ANYRTC_SCTP_TRANSPORT_PPID_DCEP);
    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
//    spa.sendv_sndinfo.snd_sid = channel->sid;
//    spa.sendv_sndinfo.snd_flags = SCTP_EOR;
//    if ((channel->state == DATA_CHANNEL_OPEN) && (channel->unordered)) {
//        spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
//    }
//    spa.sendv_sndinfo.snd_ppid = htonl(ANYRTC_SCTP_TRANSPORT_PPID_DCEP);
//    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
//    if (channel->pr_policy == SCTP_PR_SCTP_TTL || channel->pr_policy == SCTP_PR_SCTP_RTX) {
//        spa.sendv_prinfo.pr_policy = channel->pr_policy;
//        spa.sendv_prinfo.pr_value = channel->pr_value;
//        spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
//    }

    // Connected?
    // TODO
//    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
    length = usrsctp_sendv(
            transport->socket, mbuf_buf(buffer), mbuf_get_left(buffer), NULL, 0,
            &spa, (socklen_t) sizeof(spa), SCTP_SENDV_SPA, 0);
    if (length < 0) {
        DEBUG_WARNING("Could not send message, reason: %m\n", errno);
        return anyrtc_error_to_code(errno);
    }
    return ANYRTC_CODE_SUCCESS;
//    }

    // Buffer message
    // TODO
    DEBUG_WARNING("SHOULD BUFFER MESSAGE\n");
//    error = anyrtc_message_buffer_append(&transport->buffered_messages_out, NULL, buffer);
//    if (error) {
//        DEBUG_WARNING("Could not buffer outgoing packet, reason: %s\n",
//                      anyrtc_code_to_str(error));
//    } else {
//        DEBUG_PRINTF("Buffered outgoing packet of size %zu\n", mbuf_get_left(buffer));
//    }
//    return ANYRTC_CODE_SUCCESS;
}

