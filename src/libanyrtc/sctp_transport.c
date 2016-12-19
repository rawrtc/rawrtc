#include <stdio.h> // fopen
#include <string.h> // memcpy
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM, linger, sockaddr_storage
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#define SCTP_DEBUG
#include <usrsctp.h> // usrsctp*
#include <anyrtc.h>
#include "main.h"
#include "utils.h"
#include "message_buffer.h"
#include "dtls_transport.h"
#include "data_transport.h"
#include "sctp_data_channel.h"
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// SCTP send context (needed when buffering)
struct send_context {
    unsigned int info_type;
    union {
        struct sctp_sndinfo sndinfo;
        struct sctp_prinfo prinfo;
        struct sctp_authinfo authinfo;
        struct sctp_sendv_spa spa;
    } info;
    int flags;
};

// Initialised flag
static bool initialized = false;

// Events to subscribe to
static uint16_t const sctp_events[] = {
    SCTP_ASSOC_CHANGE,
//    SCTP_PEER_ADDR_CHANGE,
//    SCTP_REMOTE_ERROR,
//    SCTP_SHUTDOWN_EVENT,
//    SCTP_ADAPTATION_INDICATION,
//    SCTP_SEND_FAILED_EVENT,
    SCTP_STREAM_RESET_EVENT,
    SCTP_STREAM_CHANGE_EVENT,
//    SCTP_SENDER_DRY_EVENT
};
static size_t const sctp_events_length = sizeof(sctp_events) / sizeof(sctp_events[0]);

/*
 * Get the corresponding name for an SCTP transport state.
 */
char const * const anyrtc_sctp_transport_state_to_name(
        enum anyrtc_sctp_transport_state const state
) {
    switch (state) {
        case ANYRTC_SCTP_TRANSPORT_STATE_NEW:
            return "new";
        case ANYRTC_SCTP_TRANSPORT_STATE_CONNECTING:
            return "connecting";
        case ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case ANYRTC_SCTP_TRANSPORT_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Dump an SCTP packet into a trace file.
 */
static void trace_packet(
        struct anyrtc_sctp_transport* const transport,
        void* const buffer,
        size_t const length,
        int const direction
) {
    char* dump_buffer;

    // Have trace handle?
    if (!transport->trace_handle) {
        return;
    }

    // Trace (if trace handle)
    dump_buffer = usrsctp_dumppacket(buffer, length, direction);
    if (dump_buffer) {
        fprintf(transport->trace_handle, "%s", dump_buffer);
        usrsctp_freedumpbuffer(dump_buffer);
        fflush(transport->trace_handle);
    }
}

/*
 * Send outstanding buffered SCTP messages.
 */
static void sctp_send_outstanding(
        struct mbuf* const buffer,
        void* const context,
        void* const arg
) {
    struct anyrtc_sctp_transport* const transport = arg;
    struct send_context* const send_context = context;
    enum anyrtc_code error;
    void* info;
    socklen_t info_size;

    // Determine info pointer and info size
    switch (send_context->info_type) {
        case SCTP_SENDV_NOINFO:
            info = NULL;
            info_size = 0;
            break;
        case SCTP_SENDV_SNDINFO:
            info = (void*) &send_context->info.sndinfo;
            info_size = sizeof(send_context->info.sndinfo);
            break;
        case SCTP_SENDV_PRINFO:
            info = (void*) &send_context->info.prinfo;
            info_size = sizeof(send_context->info.prinfo);
            break;
        case SCTP_SENDV_AUTHINFO:
            info = (void*) &send_context->info.authinfo;
            info_size = sizeof(send_context->info.authinfo);
            break;
        case SCTP_SENDV_SPA:
            info = (void*) &send_context->info.spa;
            info_size = sizeof(send_context->info.spa);
            break;
        default:
            error = ANYRTC_CODE_INVALID_STATE;
            goto out;
    }

    // Send
    error = anyrtc_sctp_transport_send(
            transport, buffer, info, info_size, send_context->info_type, send_context->flags);
    if (error) {
        goto out;
    }

out:
    if (error) {
        DEBUG_WARNING("Could not send buffered message, reason: %s\n",
                      anyrtc_code_to_str(error));
    }
}

/*
 * Change the state of the SCTP transport.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_state(
        struct anyrtc_sctp_transport* const transport,
        enum anyrtc_sctp_transport_state const state
) {
    // Closed?
    if (state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        // TODO: Close all data channels (?)

        // Remove from DTLS transport
        // Note: No NULL checking needed as the function will do that for us
        anyrtc_dtls_transport_clear_data_transport(transport->dtls_transport);

        // Close socket and deregister transport
        if (transport->socket) {
            usrsctp_close(transport->socket);
            usrsctp_deregister_address(transport);
            transport->socket = NULL;
        }

        // Close trace file (if any)
        if (transport->trace_handle) {
            if (fclose(transport->trace_handle)) {
                DEBUG_WARNING("Could not close trace file, reason: %m\n", errno);
            }
        }
    }

    // Set state
    transport->state = state;

    // Connected?
    // Note: This needs to be done after the state has been updated because it uses the
    //       send function which checks the state.
    if (state == ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        // Send buffered outgoing SCTP packets
        enum anyrtc_code const error = anyrtc_message_buffer_clear(
                &transport->buffered_messages, sctp_send_outstanding, transport);
        if (error) {
            DEBUG_WARNING("Could not send buffered messages, reason: %s\n",
                          anyrtc_code_to_str(error));
        }
    }

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }
}

/*
 * Print debug information for an SCTP association change event.
 */
int debug_association_change_event(
        struct re_printf* const pf,
        struct sctp_assoc_change* const event
) {
    int err = 0;
    uint_fast32_t length;
    uint_fast32_t i;

    switch (event->sac_state) {
        case SCTP_COMM_UP:
            err |= re_hprintf(pf, "SCTP_COMM_UP");
            break;
        case SCTP_COMM_LOST:
            err |= re_hprintf(pf, "SCTP_COMM_LOST");
            break;
        case SCTP_RESTART:
            err |= re_hprintf(pf, "SCTP_RESTART");
            break;
        case SCTP_SHUTDOWN_COMP:
            err |= re_hprintf(pf, "SCTP_SHUTDOWN_COMP");
            break;
        case SCTP_CANT_STR_ASSOC:
            err |= re_hprintf(pf, "SCTP_CANT_STR_ASSOC");
            break;
        default:
            err |= re_hprintf(pf, "???");
            break;
    }
    err |= re_hprintf(pf, ", streams (in/out) = (%u/%u)",
               event->sac_inbound_streams, event->sac_outbound_streams);
    length = event->sac_length - sizeof(*event);
    if (length > 0) {
        switch (event->sac_state) {
            case SCTP_COMM_UP:
            case SCTP_RESTART:
                err |= re_hprintf(pf, ", supports");
                for (i = 0; i < length; ++i) {
                    switch (event->sac_info[i]) {
                        case SCTP_ASSOC_SUPPORTS_PR:
                            err |= re_hprintf(pf, " PR");
                            break;
                        case SCTP_ASSOC_SUPPORTS_AUTH:
                            err |= re_hprintf(pf, " AUTH");
                            break;
                        case SCTP_ASSOC_SUPPORTS_ASCONF:
                            err |= re_hprintf(pf, " ASCONF");
                            break;
                        case SCTP_ASSOC_SUPPORTS_MULTIBUF:
                            err |= re_hprintf(pf, " MULTIBUF");
                            break;
                        case SCTP_ASSOC_SUPPORTS_RE_CONFIG:
                            err |= re_hprintf(pf, " RE-CONFIG");
                            break;
                        default:
                            err |= re_hprintf(pf, " ??? (0x%02x)", event->sac_info[i]);
                            break;
                    }
                }
                break;
            case SCTP_COMM_LOST:
            case SCTP_CANT_STR_ASSOC:
                err |= re_hprintf(pf, ", ABORT =");
                for (i = 0; i < length; ++i) {
                    err |= re_hprintf(pf, " 0x%02x", event->sac_info[i]);
                }
                break;
            default:
                break;
        }
    }
    err |= re_hprintf(pf, "\n");
    return err;
}

/*
 * Handle SCTP association change event.
 */
static void handle_association_change_event(
        struct anyrtc_sctp_transport* const transport,
        struct sctp_assoc_change* const event
) {
    // Print debug output for event
    DEBUG_PRINTF("Association change: %H", debug_association_change_event, event);

    // TODO: Handle
    switch (event->sac_state) {
        case SCTP_COMM_UP:
            // Connected
            if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CONNECTING) {
                set_state(transport, ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED);
            }
            break;
        case SCTP_CANT_STR_ASSOC:
        case SCTP_SHUTDOWN_COMP:
        case SCTP_COMM_LOST:
            // Disconnected
            // TODO: Is this the correct behaviour?
            if (transport->state != ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
                set_state(transport, ANYRTC_SCTP_TRANSPORT_STATE_CLOSED);
            }
            break;
        default:
            break;
    }
}

/*
 * Handle SCTP notification.
 */
static void handle_notification(
        struct anyrtc_sctp_transport* const transport,
        struct mbuf* const buffer
) {
    union sctp_notification* const notification = (union sctp_notification*) buffer->buf;

    // TODO: Are all of these checks necessary or can we reduce that?
    if (buffer->end > UINT32_MAX ||
            notification->sn_header.sn_length > SIZE_MAX ||
            notification->sn_header.sn_length != buffer->end) {
        return;
    }

    // Handle notification by type
    switch (notification->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            handle_association_change_event(transport, &notification->sn_assoc_change);
        case SCTP_STREAM_RESET_EVENT:
            // TODO: Handle
            // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.7
            DEBUG_WARNING("TODO: HANDLE STREAM RESET\n");
            // handle_stream_reset_event(transport, &(notification->sn_strreset_event));
            break;
        case SCTP_STREAM_CHANGE_EVENT:
            // TODO: Handle
            DEBUG_WARNING("TODO: HANDLE STREAM CHANGE\n");
            // handle_stream_change_event(transport, ...);
            break;
        default:
            DEBUG_WARNING("Unexpected notification event: %"PRIu16"\n",
                          notification->sn_header.sn_type);
            break;
    }
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

    // Lock event loop mutex
    anyrtc_thread_enter();

    // Closed?
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring SCTP packet ready event, transport is closed\n");
        goto out;
    }

    // Trace (if trace handle)
    // Note: No need to check if NULL as the function does it for us
    trace_packet(transport, buffer, length, SCTP_DUMP_OUTBOUND);

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
    }

    // Handle error
    if (error) {
        DEBUG_WARNING("Could not send packet, reason: %s\n", anyrtc_code_to_str(error));
        goto out;
    }

out:
    // Unlock event loop mutex
    anyrtc_thread_leave();

    // TODO: What does the return code do?
    return 0;
}

/*
 * Handle usrsctp events.
 * TODO: Handle graceful and non-graceful shutdown (should raise an error event)
 * https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.2
 */
static void upcall_handler(
        struct socket* sock,
        void* arg,
        int flags
) {
    struct anyrtc_sctp_transport* const transport = arg;
    int events = usrsctp_get_events(sock);

    // Lock event loop mutex
    anyrtc_thread_enter();

    // Closed?
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring SCTP upcall event, transport is closed\n");
        goto out;
    }

    // Error?
    if (events & SCTP_EVENT_ERROR) {
        // TODO: What am I supposed to do with this information?
        DEBUG_WARNING("TODO: Handle SCTP error event\n");
    }

read:
    // Can read?
    if (events & SCTP_EVENT_READ) {
        struct mbuf* buffer;
        ssize_t length;
        struct sctp_rcvinfo info = {0};
        socklen_t info_length = sizeof(info);
        unsigned int info_type = 0;
        int recv_flags = 0;
        enum anyrtc_code error;

        // TODO: Get next message size
        // TODO: Can we get the COMPLETE message size or just the current message size?

        // Create buffer
        buffer = mbuf_alloc(ANYRTC_SCTP_TRANSPORT_DEFAULT_BUFFER);
        if (!buffer) {
            DEBUG_WARNING("Cannot allocate buffer, no memory");
            // TODO: This needs to be handled in a better way, otherwise it's probably going
            // to cause another read call which calls this handler again resulting in an infinite
            // loop.
            goto write;
        }

        // Receive notification or data
        length = usrsctp_recvv(
                sock, buffer->buf, buffer->size, NULL, NULL,
                &info, &info_length, &info_type, &recv_flags);
        if (length < 0) {
            DEBUG_WARNING("SCTP receive failed, reason: %m\n", errno);
            // TODO: What now? Close?
            goto write;
        }

        // Update buffer position and end
        buffer->end = (size_t) length;

        // Handle notification
        if (recv_flags & MSG_NOTIFICATION) {
            handle_notification(transport, buffer);
            goto write;
        }

        // Check state
        if (transport->state != ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
            DEBUG_WARNING("Ignored incoming data before state 'connected'\n");
            goto write;
        }

        // Have info?
        if (info_type != SCTP_RECVV_RCVINFO) {
            DEBUG_WARNING("Cannot handle incoming data without SCTP rcvfinfo\n");
            goto write;
        }

        // Pass data to SCTP data channel
        error = anyrtc_sctp_data_channel_receive_handler(transport, buffer, &info);
        if (error) {
            DEBUG_WARNING("Could not handle incoming SCTP data channel message, reason: %s\n",
                          anyrtc_code_to_str(error));
        }

// Note: Label must be here to ensure that the buffer is being free'd
write:
        // Dereference
        mem_deref(buffer);
    }

    // Can write?
    // TODO: How often is this called? What does 'write' tell me?
    if (events & SCTP_EVENT_WRITE) {
        DEBUG_WARNING("TODO: CAN WRITE\n");
    }

out:
    // Unlock event loop mutex
    anyrtc_thread_leave();
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
    trace_packet(transport, mbuf_buf(buffer), length, SCTP_DUMP_INBOUND);

    // Feed into SCTP socket
    // TODO: What about ECN bits?
    DEBUG_PRINTF("Feeding SCTP packet of %zu bytes\n", length);
    usrsctp_conninput(transport, mbuf_buf(buffer), length, 0);
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_sctp_transport_destroy(
        void* const arg
) {
    struct anyrtc_sctp_transport* const transport = arg;

    // Stop transport
    anyrtc_sctp_transport_stop(transport);

    // Dereference
    list_flush(&transport->buffered_messages);
    mem_deref(transport->dtls_transport);
}

/*
 * Create an SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_create(
        struct anyrtc_sctp_transport** const transportp, // de-referenced
        struct anyrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t port, // zeroable
        anyrtc_data_channel_handler* const data_channel_handler, // nullable
        anyrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
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
    enum anyrtc_code error;
    int option_value;
    struct sockaddr_conn peer = {0};

    // Check arguments
    if (!transportp || !dtls_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check DTLS transport state
    if (dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED
            || dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_FAILED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Set default port (if 0)
    if (port == 0) {
        port = ANYRTC_SCTP_TRANSPORT_DEFAULT_PORT;
    }

    // Check if a data transport is already registered
    error = anyrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Initialise usrsctp
    if (!initialized) {
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
        usrsctp_sysctl_set_sctp_asconf_enable(0);

        // Disable the Authentication extension
        usrsctp_sysctl_set_sctp_auth_enable(0);

        // Disable the NR-SACK extension (not standardised)
        usrsctp_sysctl_set_sctp_nrsack_enable(0);

        // Disable the Packet Drop Report extension (not standardised)
        usrsctp_sysctl_set_sctp_pktdrop_enable(0);

        // Enable the Partial Reliability extension
        usrsctp_sysctl_set_sctp_pr_enable(1);

        // Set amount of incoming streams
        usrsctp_sysctl_set_sctp_nr_incoming_streams_default(
                ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS);

        // Set amount of outgoing streams
        usrsctp_sysctl_set_sctp_nr_outgoing_streams_default(
                ANYRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS);

        // TODO: Enable SCTP ndata

        // Initialised
        initialized = true;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), anyrtc_sctp_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = ANYRTC_SCTP_TRANSPORT_STATE_NEW; // TODO: Raise state (delayed)?
    transport->port = port;
    transport->dtls_transport = mem_ref(dtls_transport);
    transport->data_channel_handler = data_channel_handler;
    transport->state_change_handler = state_change_handler;
    transport->arg = arg;
    list_init(&transport->buffered_messages);

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
    DEBUG_PRINTF("Creating SCTP socket\n");
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
    if (!transport->socket) {
        DEBUG_WARNING("Could not create socket, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Register instance
    usrsctp_register_address(transport);

    // Make socket non-blocking
    if (usrsctp_set_non_blocking(transport->socket, 1)) {
        DEBUG_WARNING("Could not set to non-blocking, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Set event callback
    if (usrsctp_set_upcall(transport->socket, upcall_handler, transport)) {
        DEBUG_WARNING("Could not set event callback (upcall), reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Enable the Stream Reconfiguration extension
    av.assoc_id = SCTP_ALL_ASSOC;
    av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
                           &av, sizeof(struct sctp_assoc_value))) {
        DEBUG_WARNING("Could not enable stream reconfiguration extension, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Set MTU (1200|1280 (IPv4|IPv6) - UDP - DTLS (cipher suite dependent) - SCTP (12)
    // https://github.com/ortclib/ortclib-cpp/blob/master/ortc/cpp/ortc_SCTPTransport.cpp#L2143

    // We want info
    option_value = 1;
    if (usrsctp_setsockopt(
            transport->socket, IPPROTO_SCTP, SCTP_RECVRCVINFO,
            &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not set socket option, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Discard pending packets when closing
    // (so we don't get a callback when the transport is already free'd)
    // TODO: Find a way to use graceful shutdown instead, otherwise the other peer would raise an
    // error indication (https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.2)
    linger_option.l_onoff = 1;
    linger_option.l_linger = 0;
    if (usrsctp_setsockopt(transport->socket, SOL_SOCKET, SO_LINGER,
                           &linger_option, sizeof(linger_option))) {
        DEBUG_WARNING("Could not set linger options, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Set no delay option (disable nagle)
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_NODELAY,
                           &av.assoc_value, sizeof(av.assoc_value))) {
        DEBUG_WARNING("Could not set no-delay, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
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
            error = anyrtc_error_to_code(errno);
            goto out;
        }
    }

    // Bind local address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(peer);
    peer.sconn_port = htons(transport->port);
    peer.sconn_addr = transport;
    if (usrsctp_bind(transport->socket, (struct sockaddr*) &peer, sizeof(peer))) {
        DEBUG_WARNING("Could not bind local address, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Attach to ICE transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = anyrtc_dtls_transport_set_data_transport(
            transport->dtls_transport, dtls_receive_handler, transport);
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

/*
 * Get the SCTP data transport instance.
 */
enum anyrtc_code anyrtc_sctp_transport_get_data_transport(
        struct anyrtc_data_transport** const transportp, // de-referenced
        struct anyrtc_sctp_transport* const sctp_transport // referenced
) {
    // Check arguments
    if (!sctp_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check SCTP transport state
    if (sctp_transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Create data transport
    return anyrtc_data_transport_create(
            transportp, ANYRTC_DATA_TRANSPORT_TYPE_SCTP, sctp_transport,
            NULL, NULL, NULL); // TODO: REPLACE NULL
}

/*
 * Start the SCTP transport.
 */
enum anyrtc_code anyrtc_sctp_transport_start(
        struct anyrtc_sctp_transport* const transport,
        struct anyrtc_sctp_capabilities* const remote_capabilities // copied
) {
    struct sockaddr_conn peer = {0};
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;

    // Check arguments
    if (!transport || !remote_capabilities) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state != ANYRTC_SCTP_TRANSPORT_STATE_NEW) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Set remote address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(peer);
    // TODO: Open an issue about missing remote port on ORTC spec.
    peer.sconn_port = htons(remote_capabilities->port);
    peer.sconn_addr = transport;

    // Connect
    DEBUG_PRINTF("Connecting to peer\n");
    if (usrsctp_connect(transport->socket, (struct sockaddr*) &peer, sizeof(peer)) &&
            errno != EINPROGRESS) {
        DEBUG_WARNING("Could not connect, reason: %m\n", errno);
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Initiate Path MTU discovery (https://tools.ietf.org/html/rfc4821)
    // by using probing messages (https://tools.ietf.org/html/rfc4820)
    // see https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-5

    // Transition to connecting state
    set_state(transport, ANYRTC_SCTP_TRANSPORT_STATE_CONNECTING);

out:
    if (error) {
        set_state(transport, ANYRTC_SCTP_TRANSPORT_STATE_CLOSED);
    }
    return error;
}


/*
 * Stop and close the DTLS transport.
 */
enum anyrtc_code anyrtc_sctp_transport_stop(
        struct anyrtc_sctp_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_SUCCESS;
    }

    // Update state
    set_state(transport, ANYRTC_SCTP_TRANSPORT_STATE_CLOSED);
    return ANYRTC_CODE_SUCCESS;

    // TODO: Anything missing?
}

/*
 * Send a data message over the SCTP transport.
 * TODO: Add partial reliability options.
 */
enum anyrtc_code anyrtc_sctp_transport_send(
        struct anyrtc_sctp_transport* const transport,
        struct mbuf* const buffer,
        void* const info,
        socklen_t const info_size,
        unsigned int const info_type,
        int const flags
) {
    ssize_t length;
    struct send_context* send_context = NULL;
    enum anyrtc_code error;

    // Check arguments
    if (!transport || !buffer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // TODO: Move to DCEP
    // Set SCTP stream, protocol identifier, flags, partial reliability, ...
//    spa.sendv_sndinfo.snd_sid = 1;
//    spa.sendv_sndinfo.snd_flags = SCTP_EOR;
//    spa.sendv_sndinfo.snd_ppid = htonl(ANYRTC_SCTP_TRANSPORT_PPID_DCEP);
//    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;
//
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
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        length = usrsctp_sendv(
                transport->socket, mbuf_buf(buffer), mbuf_get_left(buffer), NULL, 0,
                info, info_size, info_type, flags);
        if (length < 0) {
            return anyrtc_error_to_code(errno);
        }
        return ANYRTC_CODE_SUCCESS;
    }

    // Allocate context
    send_context = mem_zalloc(sizeof(*send_context), NULL);
    if (!send_context) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set context fields
    send_context->info_type = info_type;
    send_context->flags = flags;

    // Copy info data (if any)
    if (info_type != SCTP_SENDV_NOINFO && info) {
        // Copy info data according to type
        // Note: info_size will be ignored for buffered messages
        switch (info_type) {
            case SCTP_SENDV_SNDINFO:
                memcpy(&send_context->info.sndinfo, info, sizeof(send_context->info.sndinfo));
                break;
            case SCTP_SENDV_PRINFO:
                memcpy(&send_context->info.prinfo, info, sizeof(send_context->info.prinfo));
                break;
            case SCTP_SENDV_AUTHINFO:
                memcpy(&send_context->info.authinfo, info, sizeof(send_context->info.authinfo));
                break;
            case SCTP_SENDV_SPA:
                memcpy(&send_context->info.spa, info, sizeof(send_context->info.spa));
                break;
            default:
                error = ANYRTC_CODE_INVALID_STATE;
                goto out;
        }
    }

    // Buffer message
    error = anyrtc_message_buffer_append(&transport->buffered_messages, buffer, send_context);
    if (error) {
        goto out;
    }

    // Buffered message
    DEBUG_PRINTF("Buffered outgoing packet of size %zu\n", mbuf_get_left(buffer));

out:
    // Dereference
    mem_deref(send_context);

    return error;
}

/*
 * Get local SCTP capabilities of a transport.
 */
enum anyrtc_code anyrtc_sctp_transport_get_capabilities(
        struct anyrtc_sctp_capabilities** const capabilitiesp, // de-referenced
        struct anyrtc_sctp_transport* const transport
) {
    struct anyrtc_sctp_capabilities* capabilities;

    // Check arguments
    if (!capabilitiesp || !transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Allocate capabilities
    capabilities = mem_zalloc(sizeof(*capabilities), NULL);
    if (!capabilities) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    capabilities->port = transport->port;
    capabilities->max_message_size = ANYRTC_SCTP_TRANSPORT_MAX_MESSAGE_SIZE;

    // Set pointer & done
    *capabilitiesp = capabilities;
    return ANYRTC_CODE_SUCCESS;
}
