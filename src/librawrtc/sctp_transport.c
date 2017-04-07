#include <stdio.h> // fopen
#include <string.h> // memcpy, strlen
#include <errno.h> // errno
#include <sys/socket.h> // AF_INET, SOCK_STREAM, linger
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP, htons
#if (RAWRTC_DEBUG_LEVEL >= 7)
    #define SCTP_DEBUG
#endif
#include <usrsctp.h> // usrsctp*
#include <rawrtc.h>
#include "main.h"
#include "utils.h"
#include "message_buffer.h"
#include "dtls_transport.h"
#include "data_transport.h"
#include "data_channel_parameters.h"
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

// SCTP outgoing message context (needed when buffering)
struct send_context {
    unsigned int info_type;
    union {
        struct sctp_sndinfo sndinfo;
        struct sctp_sendv_spa spa;
    } info;
    int flags;
};

// Events to subscribe to
static uint16_t const sctp_events[] = {
    SCTP_ASSOC_CHANGE,
//    SCTP_PEER_ADDR_CHANGE,
//    SCTP_REMOTE_ERROR,
    SCTP_PARTIAL_DELIVERY_EVENT,
    SCTP_SEND_FAILED_EVENT,
    SCTP_SENDER_DRY_EVENT,
    SCTP_SHUTDOWN_EVENT,
//    SCTP_ADAPTATION_INDICATION,
    SCTP_STREAM_CHANGE_EVENT,
    SCTP_STREAM_RESET_EVENT
};
static size_t const sctp_events_length = ARRAY_SIZE(sctp_events);

static enum rawrtc_code channel_context_create(
    struct rawrtc_sctp_data_channel_context** const contextp, // de-referenced, not checked
    uint16_t const sid,
    bool const can_send_unordered
);

static bool channel_registered(
    struct rawrtc_sctp_transport* const transport, // not checked
    struct rawrtc_data_channel* const channel // not checked
);

static void channel_register(
    struct rawrtc_sctp_transport* const transport, // not checked
    struct rawrtc_data_channel* const channel, // referenced, not checked
    struct rawrtc_sctp_data_channel_context* const context, // referenced, not checked
    bool const raise_event
);

enum rawrtc_code sctp_transport_send(
    struct rawrtc_sctp_transport* const transport, // not checked
    struct mbuf* const buffer, // not checked
    void* const info, // not checked
    socklen_t const info_size,
    unsigned int const info_type,
    int const flags
);

/*
 * Parse a data channel open message.
 */
static enum rawrtc_code data_channel_open_message_parse(
        struct rawrtc_data_channel_parameters** const parametersp, // de-referenced, not checked
        uint_fast16_t* const priorityp, // de-referenced, not checked
        uint16_t const id,
        struct mbuf* const buffer // not checked
) {
    uint_fast8_t channel_type;
    uint_fast16_t priority;
    uint_fast32_t reliability_parameter;
    uint_fast16_t label_length;
    uint_fast16_t protocol_length;
    int err;
    char* label = NULL;
    char* protocol = NULL;
    enum rawrtc_code error;

    // Check length
    // Note: -1 because we've already removed the message type
    if (mbuf_get_left(buffer) < (RAWRTC_DCEP_MESSAGE_OPEN_BASE_SIZE - 1)) {
        return RAWRTC_CODE_INVALID_MESSAGE;
    }

    // Get fields
    channel_type = mbuf_read_u8(buffer);
    priority = ntohs(mbuf_read_u16(buffer));
    reliability_parameter = ntohl(mbuf_read_u32(buffer));
    label_length = ntohs(mbuf_read_u16(buffer));
    protocol_length = ntohs(mbuf_read_u16(buffer));

    // Validate channel type
    switch (channel_type) {
        case RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED:
        case RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED:
        case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_RETRANSMIT:
        case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_RETRANSMIT:
        case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_TIMED:
        case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_TIMED:
            break;
        default:
            return RAWRTC_CODE_INVALID_MESSAGE;
    }

    // Get label
#if (UINT_FAST16_MAX > SIZE_MAX)
    if (label_length > SIZE_MAX) {
        return RAWRTC_CODE_INVALID_MESSAGE;
    }
#endif
    if (mbuf_get_left(buffer) < label_length) {
        return RAWRTC_CODE_INVALID_MESSAGE;
    }
    if (label_length > 0) {
        err = mbuf_strdup(buffer, &label, label_length);
        if (err) {
            error = rawrtc_error_to_code(err);
            goto out;
        }
    }

    // Get protocol
#if (UINT_FAST16_MAX > SIZE_MAX)
    if (protocol_length > SIZE_MAX) {
        return RAWRTC_CODE_INVALID_MESSAGE;
    }
#endif
    if (mbuf_get_left(buffer) < protocol_length) {
        return RAWRTC_CODE_INVALID_MESSAGE;
    }
    if (protocol_length > 0) {
        err = mbuf_strdup(buffer, &protocol, protocol_length);
        if (err) {
            error = rawrtc_error_to_code(err);
            goto out;
        }
    }

    // Create data channel parameters
    error = rawrtc_data_channel_parameters_create_internal(
            parametersp, label, (enum rawrtc_data_channel_type) channel_type,
            (uint32_t) reliability_parameter, protocol, false, id);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(label);
    mem_deref(protocol);

    if (!error) {
        // Set priority value
        *priorityp = priority;
    }
    return error;
}

/*
 * Create a data channel open message.
 */
static enum rawrtc_code data_channel_open_message_create(
        struct mbuf** const bufferp, // de-referenced, not checked
        struct rawrtc_data_channel_parameters const * const parameters // not checked
) {
    size_t label_length;
    size_t protocol_length;
    struct mbuf* buffer;
    int err;

    // Get length of label and protocol
    label_length = parameters->label ? strlen(parameters->label) : 0;
    protocol_length = parameters->protocol ? strlen(parameters->protocol) : 0;

    // Check string length
#if (SIZE_MAX > UINT16_MAX)
    if (label_length > UINT16_MAX || protocol_length > UINT16_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
#endif

    // Allocate
    buffer = mbuf_alloc(RAWRTC_DCEP_MESSAGE_OPEN_BASE_SIZE + label_length + protocol_length);
    if (!buffer) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    err = mbuf_write_u8(buffer, RAWRTC_DCEP_MESSAGE_TYPE_OPEN);
    err |= mbuf_write_u8(buffer, parameters->channel_type);
    err |= mbuf_write_u16(buffer, htons(RAWRTC_DCEP_CHANNEL_PRIORITY_NORMAL)); // TODO: Ok?
    err |= mbuf_write_u32(buffer, htonl(parameters->reliability_parameter));
    err |= mbuf_write_u16(buffer, htons((uint16_t) label_length));
    err |= mbuf_write_u16(buffer, htons((uint16_t) protocol_length));
    if (parameters->label) {
        err |= mbuf_write_mem(buffer, (uint8_t *) parameters->label, label_length);
    }
    if (parameters->protocol) {
        err |= mbuf_write_mem(buffer, (uint8_t *) parameters->protocol, protocol_length);
    }

    if (err) {
        mem_deref(buffer);
        return rawrtc_error_to_code(err);
    } else {
        // Set position
        mbuf_set_pos(buffer, 0);

        // Set pointer & done
        *bufferp = buffer;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Create a data channel ack message.
 */
static enum rawrtc_code data_channel_ack_message_create(
        struct mbuf** const bufferp // de-referenced, not checked
) {
    int err;

    // Allocate
    struct mbuf* const buffer = mbuf_alloc(RAWRTC_DCEP_MESSAGE_ACK_BASE_SIZE);
    if (!buffer) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    err = mbuf_write_u8(buffer, RAWRTC_DCEP_MESSAGE_TYPE_ACK);

    if (err) {
        mem_deref(buffer);
        return rawrtc_error_to_code(err);
    } else {
        // Set position
        mbuf_set_pos(buffer, 0);

        // Set pointer & done
        *bufferp = buffer;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the corresponding name for an SCTP transport state.
 */
char const * const rawrtc_sctp_transport_state_to_name(
        enum rawrtc_sctp_transport_state const state
) {
    switch (state) {
        case RAWRTC_SCTP_TRANSPORT_STATE_NEW:
            return "new";
        case RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING:
            return "connecting";
        case RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case RAWRTC_SCTP_TRANSPORT_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Dump an SCTP packet into a trace file.
 */
static void trace_packet(
        struct rawrtc_sctp_transport* const transport,
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
 * Send a deferred SCTP message.
 */
static bool sctp_send_deferred_message(
        struct mbuf* const buffer,
        void* const context,
        void* const arg
) {
    struct rawrtc_sctp_transport* const transport = arg;
    struct send_context* const send_context = context;
    enum rawrtc_code error;
    void* info;
    socklen_t info_size;

    // Determine info pointer and info size
    switch (send_context->info_type) {
        case SCTP_SENDV_SNDINFO:
            info = (void*) &send_context->info.sndinfo;
            info_size = sizeof(send_context->info.sndinfo);
            break;
        case SCTP_SENDV_SPA:
            info = (void*) &send_context->info.spa;
            info_size = sizeof(send_context->info.spa);
            break;
        default:
            error = RAWRTC_CODE_INVALID_STATE;
            goto out;
    }

    // Try sending
    DEBUG_PRINTF("Sending deferred message\n");
    error = sctp_transport_send(
            transport, buffer, info, info_size, send_context->info_type, send_context->flags);
    switch (error) {
        case RAWRTC_CODE_TRY_AGAIN_LATER:
            // Stop iterating through message queue
            return false;
        case RAWRTC_CODE_MESSAGE_TOO_LONG:
            DEBUG_WARNING("Incorrect message size guess, report this!\n");
        default:
            goto out;
            break;
    }

out:
    if (error) {
        DEBUG_WARNING("Could not send buffered message, reason: %s\n",
                      rawrtc_code_to_str(error));
    }

    // Continue iterating through message queue
    return true;
}

/*
 * Send all deferred messages.
 */
static enum rawrtc_code sctp_send_deferred_messages(
        struct rawrtc_sctp_transport* const transport // not checked
) {
    // Send buffered outgoing SCTP packets
    return rawrtc_message_buffer_clear(
            &transport->buffered_messages_outgoing, sctp_send_deferred_message, transport);
}

/*
 * Send an SCTP message on the data channel.
 * TODO: Add EOR marking and some kind of an id (does ndata provide that?)
 */
static enum rawrtc_code send_message(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_data_channel* const channel, // nullable (if DCEP message)
        struct rawrtc_sctp_data_channel_context* const context, // not checked
        struct mbuf* const buffer, // not checked
        uint_fast32_t const ppid
) {
    struct sctp_sendv_spa spa = {0};
    enum rawrtc_code error;

    // Set stream identifier, protocol identifier and flags
    spa.sendv_sndinfo.snd_sid = context->sid;
    spa.sendv_sndinfo.snd_flags = SCTP_EOR; // TODO: Update signature
    spa.sendv_sndinfo.snd_ppid = htonl((uint32_t) ppid);
    spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

    // Set ordered/unordered and partial reliability policy
    if (ppid != RAWRTC_SCTP_TRANSPORT_PPID_DCEP) {
        // Check channel
        if (!channel) {
            return RAWRTC_CODE_INVALID_ARGUMENT;
        }

        // Unordered?
        if (channel->parameters->channel_type & RAWRTC_DATA_CHANNEL_TYPE_IS_UNORDERED &&
                context->flags & RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED) {
            spa.sendv_sndinfo.snd_flags |= SCTP_UNORDERED;
        }

        // Partial reliability policy
        switch (ppid) {
            case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_RETRANSMIT:
            case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_RETRANSMIT:
                // Set amount of retransmissions
                spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
                spa.sendv_prinfo.pr_value = channel->parameters->reliability_parameter;
                spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
            case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_ORDERED_TIMED:
            case RAWRTC_DATA_CHANNEL_TYPE_UNRELIABLE_UNORDERED_TIMED:
                // Set TTL
                spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_TTL;
                spa.sendv_prinfo.pr_value = channel->parameters->reliability_parameter;
                spa.sendv_flags |= SCTP_SEND_PRINFO_VALID;
            default:
                // Nothing to do
                break;
        }
    }

    // Send message
    DEBUG_PRINTF("Sending message with SID %"PRIu16", PPID: %"PRIu32"\n", context->sid, ppid);
    error = rawrtc_sctp_transport_send(
            transport, buffer, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
    if (error) {
        DEBUG_WARNING("Unable to send message, reason: %s\n", rawrtc_code_to_str(error));
        return error;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Change the states of all data channels.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_data_channel_states(
        struct rawrtc_sctp_transport* const transport, // not checked
        enum rawrtc_data_channel_state const to_state,
        enum rawrtc_data_channel_state const * const from_state // optional current state
) {
    uint_fast16_t i;

    // Set state on all data channels
    for (i = 0; i < transport->n_channels; ++i) {
        struct rawrtc_data_channel* const channel = transport->channels[i];
        if (!channel) {
            continue;
        }

        // Update state
        if (!from_state || channel->state == *from_state) {
            rawrtc_data_channel_set_state(channel, to_state);
        }
    }
}

/*
 * Close all data channels.
 * Warning: This will not use the closing procedure, use `channel_close_handler` instead.
 */
static void close_data_channels(
        struct rawrtc_sctp_transport* const transport // not checked
) {
    uint_fast16_t i;

    // Set state on all data channels
    for (i = 0; i < transport->n_channels; ++i) {
        struct rawrtc_data_channel* const channel = transport->channels[i];
        if (!channel) {
            continue;
        }

        // Update state
        DEBUG_PRINTF("Closing channel with SID %"PRIu16"\n", i);
        rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSED);

        // Un-reference
        transport->channels[i] = mem_deref(channel);
    }
}

/*
 * Change the state of the SCTP transport.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_state(
        struct rawrtc_sctp_transport* const transport, // not checked
        enum rawrtc_sctp_transport_state const state
) {
    // Closed?
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_INFO("SCTP connection closed\n");

        // Close all data channels
        close_data_channels(transport);

        // Remove from DTLS transport
        // Note: No NULL checking needed as the function will do that for us
        rawrtc_dtls_transport_clear_data_transport(transport->dtls_transport);

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
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        enum rawrtc_code error;
        enum rawrtc_data_channel_state const from_channel_state =
                RAWRTC_DATA_CHANNEL_STATE_CONNECTING;
        DEBUG_INFO("SCTP connection established\n");

        // Send deferred messages
        error = sctp_send_deferred_messages(transport);
        if (error && error != RAWRTC_CODE_STOP_ITERATION) {
            DEBUG_WARNING("Could not send deferred messages, reason: %s\n",
                          rawrtc_code_to_str(error));
        }

        // Open waiting channels
        // Note: This call must be above calling the state handler to prevent the user from
        //       being able to close the transport before the data channels are being opened.
        set_data_channel_states(transport, RAWRTC_DATA_CHANNEL_STATE_OPEN, &from_channel_state);
    }

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }
}

/*
 * Reset the outgoing stream of a data channel.
 * Note: This function will only return an error in case the stream could not be reset properly
 *       In this case, the channel will be closed and removed from the transport immediately.
 */
static enum rawrtc_code reset_outgoing_stream(
    struct rawrtc_sctp_transport* const transport, // not checked
    struct rawrtc_data_channel* const channel // not checked
) {
    struct sctp_reset_streams* reset_streams = NULL;
    size_t length;
    enum rawrtc_code error;

    // Get context
    struct rawrtc_sctp_data_channel_context* const context = channel->transport_arg;

    // Check if there are pending outgoing messages
    if (!list_isempty(&transport->buffered_messages_outgoing)) {
        context->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_PENDING_STREAM_RESET;
        return RAWRTC_CODE_SUCCESS;
    }

    // Calculate length
    length = sizeof(*reset_streams) + sizeof(uint16_t);

    // Allocate
    reset_streams = mem_zalloc(length, NULL);
    if (!reset_streams) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Set fields
    reset_streams->srs_flags = SCTP_STREAM_RESET_OUTGOING;
    reset_streams->srs_number_streams = 1;
    reset_streams->srs_stream_list[0] = context->sid;

    // Reset stream
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_RESET_STREAMS,
                           reset_streams, (socklen_t) length)) {
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Done
    DEBUG_PRINTF("Outgoing stream %"PRIu16" reset procedure started\n", context->sid);
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference
    mem_deref(reset_streams);

    if (error) {
        // Improper closing
        DEBUG_WARNING("Could not reset outgoing stream %"PRIu16", reason: %s, closing channel "
                      "improperly\n", context->sid, rawrtc_code_to_str(error));

        // Close
        rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSED);

        // Sanity check
        if (!channel_registered(transport, channel)) {
            return RAWRTC_CODE_UNKNOWN_ERROR;
        }

        // Remove from transport
        transport->channels[context->sid] = mem_deref(channel);
    }
    return error;
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
 * Print debug information for an SCTP partial delivery event.
 */
int debug_partial_delivery_event(
        struct re_printf* const pf,
        struct sctp_pdapi_event* const event
) {
    int err = 0;

    switch (event->pdapi_indication) {
        case SCTP_PARTIAL_DELIVERY_ABORTED:
            re_hprintf(pf, "Partial delivery aborted ");
            break;
        default:
            re_hprintf(pf, "??? ");
            break;
    }
    err |= re_hprintf(pf, "(flags = %x) ", event->pdapi_flags);
    err |= re_hprintf(pf, "stream = %"PRIu32" ", event->pdapi_stream);
    err |= re_hprintf(pf, "sn = %"PRIu32, event->pdapi_seq);
    err |= re_hprintf(pf, "\n");
    return err;
}

/*
 * Print debug information for an SCTP send failed event.
 */
int debug_send_failed_event(
        struct re_printf* const pf,
        struct sctp_send_failed_event* const event
) {
    int err = 0;

    if (event->ssfe_flags & SCTP_DATA_UNSENT) {
        err |= re_hprintf(pf, "Unsent ");
    }
    if (event->ssfe_flags & SCTP_DATA_SENT) {
        err |= re_hprintf(pf, "Sent ");
    }
    if (event->ssfe_flags & ~(SCTP_DATA_SENT | SCTP_DATA_UNSENT)) {
        err |= re_hprintf(pf, "(flags = %x) ", event->ssfe_flags);
    }
    err |= re_hprintf(
            pf,
            "message with PPID %"PRIu32", SID = %"PRIu16", flags: 0x%04x due to error = 0x%08x\n",
            ntohl(event->ssfe_info.snd_ppid), event->ssfe_info.snd_sid,
            event->ssfe_info.snd_flags, event->ssfe_error);
    return err;
}

/*
 * Print debug information for an SCTP stream reset event.
 */
int debug_stream_reset_event(
        struct re_printf* const pf,
        struct sctp_stream_reset_event* const event
) {
    int err = 0;
    uint_fast32_t length;
    uint_fast32_t i;

    // Get #sid's
    length = (event->strreset_length - sizeof(*event)) / sizeof(uint16_t);

    err |= re_hprintf(pf, "flags = %x, ", event->strreset_flags);
    if (event->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
        if (event->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
            err |= re_hprintf(pf, "incoming/");
        }
        err |= re_hprintf(pf, "incoming ");
    }
    if (event->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
        err |= re_hprintf(pf, "outgoing ");
    }
    err |= re_hprintf(pf, "stream ids = ");
    for (i = 0; i < length; ++i) {
        if (i > 0) {
            err |= re_hprintf(pf, ", ");
        }
        err |= re_hprintf(pf, "%"PRIu16, event->strreset_stream_list[i]);
    }
    err |= re_hprintf(pf, "\n");
    return err;
}

/*
 * Handle SCTP association change event.
 */
static void handle_association_change_event(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_assoc_change* const event
) {
    // Print debug output for event
    DEBUG_PRINTF("Association change: %H", debug_association_change_event, event);

    // Handle state
    switch (event->sac_state) {
        case SCTP_COMM_UP:
            // Connected
            if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING) {
                set_state(transport, RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED);
            }
            break;
        case SCTP_RESTART:
            // TODO: Handle?
            break;
        case SCTP_CANT_STR_ASSOC:
        case SCTP_SHUTDOWN_COMP:
        case SCTP_COMM_LOST:
            // Disconnected
            // TODO: Is this the correct behaviour?
            if (transport->state != RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
                set_state(transport, RAWRTC_SCTP_TRANSPORT_STATE_CLOSED);
            }
            break;
        default:
            break;
    }
}

/*
 * Handle SCTP partial delivery event.
 */
static void handle_partial_delivery_event(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_pdapi_event* const event
) {
    uint16_t sid;
    struct rawrtc_data_channel* channel;
    struct rawrtc_sctp_data_channel_context* context;

    // Print debug output for event
    DEBUG_PRINTF("Partial delivery event: %H", debug_partial_delivery_event, event);

    // Validate stream ID
    if (event->pdapi_stream >= UINT16_MAX) {
        DEBUG_WARNING("Invalid stream id in partial delivery event: %"PRIu32"\n",
                      event->pdapi_stream);
        return;
    }
    sid = (uint16_t) event->pdapi_stream;

    // Check if channel exists
    // TODO: Need to check if channel is open?
    if (sid >= transport->n_channels || !transport->channels[sid]) {
        DEBUG_NOTICE("No channel registered for sid %"PRIu16"\n", sid);
        return;
    }

    // Get channel and context
    channel = transport->channels[sid];
    context = channel->transport_arg;

    // Abort pending message
    if (context->buffer_inbound) {
        DEBUG_NOTICE("Abort partially delivered message of %zu bytes\n",
                     mbuf_get_left(context->buffer_inbound));
        context->buffer_inbound = mem_deref(context->buffer_inbound);

        // Sanity-check
        if (channel->options->deliver_partially) {
            DEBUG_WARNING("We deliver partially but there was a buffered message?!\n");
        }
    }

    // Pass abort notification to handler
    if (channel->options->deliver_partially) {
        enum rawrtc_data_channel_message_flag const message_flags =
                RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_ABORTED;
        if (channel->message_handler) {
            channel->message_handler(NULL, message_flags, channel->arg);
        } else {
            DEBUG_NOTICE("No message handler, message abort notification has been discarded\n");
        }
    }
}

/*
 * Handle SCTP send failed event.
 */
static void handle_send_failed_event(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_send_failed_event* const event
) {
    // Print debug output for event
    DEBUG_PRINTF("Send failed event: %H", debug_send_failed_event, event);
    (void) transport;
    (void) event;
}

/*
 * Raise buffered amount low on a data channel.
 */
static void raise_buffered_amount_low_event(
        struct rawrtc_data_channel* const channel // not checked
) {
    // Check for event handler
    if (channel->buffered_amount_low_handler) {
        // Get context
        struct rawrtc_sctp_data_channel_context* const context = channel->transport_arg;
        (void) context;

        // Raise event
        DEBUG_PRINTF("Raising buffered amount low event on channel with SID %"PRIu16"\n",
                     context->sid);
        channel->buffered_amount_low_handler(channel->arg);
    }
}

/*
 * Handle SCTP sender dry (no outstanding data) event.
 */
static void handle_sender_dry_event(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_sender_dry_event* const event
) {
    uint_fast16_t i;
    uint_fast16_t stop;
    (void) event;

    // If there are outstanding messages, don't raise an event
    if (!list_isempty(&transport->buffered_messages_outgoing)) {
        DEBUG_PRINTF("Pending messages, ignoring sender dry event\n");
        return;
    }

    // Set buffered amount low
    transport->flags |= RAWRTC_SCTP_TRANSPORT_FLAGS_BUFFERED_AMOUNT_LOW;

    // Reset counter if #channels has been reduced
    if (transport->current_channel_sid >= transport->n_channels) {
        i = 0;
    } else {
        i = transport->current_channel_sid;
    }

    // Raise event on each data channel
    stop = i;
    do {
        struct rawrtc_data_channel* const channel = transport->channels[i];
        if (channel) {
            struct rawrtc_sctp_data_channel_context* const context = channel->transport_arg;

            // Handle flags
            if (context->flags & RAWRTC_SCTP_DATA_CHANNEL_FLAGS_PENDING_STREAM_RESET) {
                // Reset pending outgoing stream
                // TODO: This should probably be handled earlier but requires having separate
                //       lists for each data channel to be sure that the stream is not reset before
                //       all pending messages have been sent.
                reset_outgoing_stream(transport, channel);
                context->flags &= ~RAWRTC_SCTP_DATA_CHANNEL_FLAGS_PENDING_STREAM_RESET;
            } else {
                // Raise event
                raise_buffered_amount_low_event(transport->channels[i]);
            }
        }

        // Update/wrap
        // Note: uint16 is sufficient here as the maximum number of channels is
        //       65534, so 65535 will still fit
        i = (i + 1) % transport->n_channels;

        // Stop if the flag has been cleared
        if (!(transport->flags & RAWRTC_SCTP_TRANSPORT_FLAGS_BUFFERED_AMOUNT_LOW)) {
            break;
        }
    } while (i != stop);

    // Update current channel SID
    transport->current_channel_sid = i;
}

/*
 * Handle stream reset event (data channel closed).
 */
static void handle_stream_reset_event(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_stream_reset_event* const event
) {
    uint_fast32_t length;
    uint_fast32_t i;

    // Get #sid's
    length = (event->strreset_length - sizeof(*event)) / sizeof(uint16_t);

    // Print debug output for event
    DEBUG_PRINTF("Stream reset event: %H", debug_stream_reset_event, event, length);

    // Ignore denied/failed events
    if (event->strreset_flags & SCTP_STREAM_RESET_DENIED
        || event->strreset_flags & SCTP_STREAM_RESET_FAILED) {
        return;
    }

    // Handle stream resets
    for (i = 0; i < length; ++i) {
        uint_fast16_t const sid = (uint_fast16_t) event->strreset_stream_list[i];
        struct rawrtc_data_channel* channel;
        struct rawrtc_sctp_data_channel_context* context;

        // Check if channel exists
        if (sid >= transport->n_channels || !transport->channels[sid]) {
            DEBUG_NOTICE("No channel registered for sid %"PRIuFAST16"\n", sid);
            continue;
        }

        // Get channel and context
        channel = transport->channels[sid];
        context = channel->transport_arg;

        // Incoming stream reset
        if (event->strreset_flags & SCTP_STREAM_RESET_INCOMING_SSN) {
            // Set flag
            channel->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_INCOMING_STREAM_RESET;

            // Reset outgoing stream (if needed)
            if (channel->state != RAWRTC_DATA_CHANNEL_STATE_CLOSING
                && channel->state != RAWRTC_DATA_CHANNEL_STATE_CLOSED) {
                if (reset_outgoing_stream(transport, channel)) {
                    // Error, channel has been closed automatically
                    continue;
                }

                // Set to closing
                rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSING);
            }
        }

        // Outgoing stream reset (this is raised from our own stream reset)
        if (event->strreset_flags & SCTP_STREAM_RESET_OUTGOING_SSN) {
            // Set flag
            channel->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_OUTGOING_STREAM_RESET;
        }

        // Close if both incoming and outgoing stream has been reset
        if (channel->flags & RAWRTC_SCTP_DATA_CHANNEL_FLAGS_INCOMING_STREAM_RESET
            && channel->flags & RAWRTC_SCTP_DATA_CHANNEL_FLAGS_OUTGOING_STREAM_RESET) {
            // Set to closed
            rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSED);

            // Remove from transport
            transport->channels[context->sid] = mem_deref(channel);
        }
    }
}

/*
 * Handle SCTP notification.
 */
static void handle_notification(
        struct rawrtc_sctp_transport* const transport,
        struct mbuf* const buffer
) {
    union sctp_notification* const notification = (union sctp_notification*) buffer->buf;

    // TODO: Are all of these checks necessary or can we reduce that?
#if (SIZE_MAX > UINT32_MAX)
    if (buffer->end > UINT32_MAX) {
        return;
    }
#endif
#if (UINT32_MAX > SIZE_MAX)
    if (notification->sn_header.sn_length > SIZE_MAX) {
        return;
    }
#endif
    if (notification->sn_header.sn_length != buffer->end) {
        return;
    }

    // Handle notification by type
    switch (notification->sn_header.sn_type) {
        case SCTP_ASSOC_CHANGE:
            handle_association_change_event(transport, &notification->sn_assoc_change);
            break;
        case SCTP_PARTIAL_DELIVERY_EVENT:
            handle_partial_delivery_event(transport, &notification->sn_pdapi_event);
            break;
        case SCTP_SEND_FAILED_EVENT:
            handle_send_failed_event(transport, &notification->sn_send_failed_event);
            break;
        case SCTP_SENDER_DRY_EVENT:
            handle_sender_dry_event(transport, &notification->sn_sender_dry_event);
            break;
        case SCTP_SHUTDOWN_EVENT:
            // TODO: Stop sending (this is a bit tricky to implement, so skipping for now)
            //handle_shutdown_event(transport, &notification->sn_shutdown_event);
            break;
        case SCTP_STREAM_CHANGE_EVENT:
            // TODO: Handle
            DEBUG_WARNING("TODO: HANDLE STREAM CHANGE\n");
            // handle_stream_change_event(transport, ...);
            break;
        case SCTP_STREAM_RESET_EVENT:
            handle_stream_reset_event(transport, &notification->sn_strreset_event);
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
    struct rawrtc_sctp_transport* const transport = arg;
    enum rawrtc_code error;
    (void) tos; // TODO: Handle?
    (void) set_df; // TODO: Handle?

    // Lock event loop mutex
    rawrtc_thread_enter();

    // Closed?
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_PRINTF("Ignoring SCTP packet ready event, transport is closed\n");
        goto out;
    }

    // Trace (if trace handle)
    // Note: No need to check if NULL as the function does it for us
    trace_packet(transport, buffer, length, SCTP_DUMP_OUTBOUND);

    // Note: We only need to copy the buffer if we add it to the outgoing queue
    if (transport->dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        struct mbuf mbuffer;

        // Note: dtls_send does not reference the buffer, so we can safely fake an mbuf structure
        // to avoid copying. This may change in the future, so be aware!
        mbuffer.buf = buffer;
        mbuffer.pos = 0;
        mbuffer.size = length;
        mbuffer.end = length;

        // Send
        error = rawrtc_dtls_transport_send(transport->dtls_transport, &mbuffer);
    } else {
        int err;

        // Allocate
        struct mbuf* const mbuffer = mbuf_alloc(length);
        if (!mbuffer) {
            DEBUG_WARNING("Could not create buffer for outgoing packet, no memory\n");
            goto out;
        }

        // Copy and set position
        err = mbuf_write_mem(mbuffer, buffer, length);
        if (err) {
            DEBUG_WARNING("Could not write to buffer, reason: %m\n", err);
            mem_deref(mbuffer);
            goto out;
        }
        mbuf_set_pos(mbuffer, 0);

        // Send (well, actually buffer...)
        error = rawrtc_dtls_transport_send(transport->dtls_transport, mbuffer);
        mem_deref(mbuffer);
    }

    // Handle error
    if (error) {
        DEBUG_WARNING("Could not send packet, reason: %s\n", rawrtc_code_to_str(error));
        goto out;
    }

out:
    // Unlock event loop mutex
    rawrtc_thread_leave();

    // TODO: What does the return code do?
    return 0;
}

/*
 * Handle data channel ack message.
 */
static void handle_data_channel_ack_message(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_rcvinfo* const info
) {
    struct rawrtc_sctp_data_channel_context* context;

    // Get channel and context
    struct rawrtc_data_channel* const channel = transport->channels[info->rcv_sid];
    if (!channel) {
        DEBUG_WARNING("Received ack on an invalid channel with SID %"PRIu16"\n", info->rcv_sid);
        goto error;
    }
    context = channel->transport_arg;

    // TODO: We should probably track the state and close the channel if an ack is being received
    //       on an already negotiated channel. For now, we only check that the ack is the first
    //       message received (which is fair enough but may not be 100% correct in the future).
    if (context->flags & RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED) {
        DEBUG_WARNING("Received ack but channel %"PRIu16" is already negotiated\n", info->rcv_sid);
        goto error;
    }

    // Messages may now be sent unordered
    context->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED;
    return;

error:
    // TODO: Reset stream with SID on error
    return;
}

/*
 * Handle data channel open message.
 */
static void handle_data_channel_open_message(
        struct rawrtc_sctp_transport* const transport,
        struct mbuf* const buffer_in,
        struct sctp_rcvinfo* const info
) {
    enum rawrtc_code error;
    struct rawrtc_data_channel_parameters* parameters;
    uint_fast16_t priority;
    struct rawrtc_data_transport* data_transport = NULL;
    struct rawrtc_data_channel* channel = NULL;
    struct rawrtc_sctp_data_channel_context* context = NULL;
    struct mbuf* buffer_out = NULL;

    // Check SID corresponds to other peer's role
    switch (transport->dtls_transport->role) {
        case RAWRTC_DTLS_ROLE_AUTO:
            // Note: This case should be impossible. If it happens, report it!
            DEBUG_WARNING("Cannot validate SID due to undetermined DTLS role\n");
            return;
        case RAWRTC_DTLS_ROLE_CLIENT:
            // Other peer must have chosen an odd SID
            if (info->rcv_sid % 2 != 1) {
                DEBUG_WARNING("Other peer incorrectly chose an even SID\n");
                return;
            }
            break;
        case RAWRTC_DTLS_ROLE_SERVER:
            // Other peer must have chosen an even SID
            if (info->rcv_sid % 2 != 0) {
                DEBUG_WARNING("Other peer incorrectly chose an odd SID\n");
                return;
            }
            break;
        default:
            return;
    }

    // Check if slot is occupied
    if (transport->channels[info->rcv_sid]) {
        DEBUG_WARNING("Other peer chose already occupied SID %"PRIu16"\n", info->rcv_sid);
        return;
    }

    // Get parameters from data channel open message
    error = data_channel_open_message_parse(&parameters, &priority, info->rcv_sid, buffer_in);
    if (error) {
        DEBUG_WARNING("Unable to parse DCEP open message, reason: %s\n", rawrtc_code_to_str(error));
        return;
    }

    // Get data transport
    error = rawrtc_sctp_transport_get_data_transport(&data_transport, transport);
    if (error) {
        DEBUG_WARNING("Unable to get data transport, reason: %s\n", rawrtc_code_to_str(error));
        goto out;
    }

    // Create data channel
    error = rawrtc_data_channel_create_internal(
            &channel, data_transport, parameters, NULL,
            NULL, NULL, NULL, NULL, NULL, NULL,
            false);
    if (error) {
        DEBUG_WARNING("Unable to create data channel, reason: %s\n", rawrtc_code_to_str(error));
        goto out;
    }

    // Allocate context to be used as an argument for the data channel handlers
    error = channel_context_create(&context, info->rcv_sid, true);
    if (error) {
        DEBUG_WARNING("Unable to create data channel context, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // TODO: Store priority for SCTP ndata,
    //       see https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.4
    (void) priority;

    // Create ack message
    buffer_out = NULL;
    error = data_channel_ack_message_create(&buffer_out);
    if (error) {
        DEBUG_WARNING("Unable to create data channel ack message, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Send message
    DEBUG_PRINTF("Sending data channel ack message for channel with SID %"PRIu16"\n", context->sid);
    error = send_message(transport, NULL, context, buffer_out, RAWRTC_SCTP_TRANSPORT_PPID_DCEP);
    if (error) {
        DEBUG_WARNING("Unable to send data channel ack message, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Register data channel
    channel_register(transport, channel, context, true);

    // TODO: Reset stream with SID on error

out:
    mem_deref(buffer_out);
    mem_deref(context);
    mem_deref(channel);
    mem_deref(data_transport);
    mem_deref(parameters);
}

/*
 * Buffer incoming messages
 *
 * Return `RAWRTC_CODE_SUCCESS` in case the message is complete and
 * should be handled. Otherwise, return `RAWRTC_CODE_NO_VALUE`.
 */
static enum rawrtc_code buffer_message_received_raise_complete(
        struct mbuf** const buffer_inboundp, // de-referenced, not checked
        struct sctp_rcvinfo* const info_inboundp, // de-referenced, not checked
        struct mbuf* const message_buffer, // not checked
        struct sctp_rcvinfo* const info, // not checked
        int const flags
) {
    bool const complete =
            (flags & MSG_EOR) &&
            info->rcv_ppid != RAWRTC_SCTP_TRANSPORT_PPID_UTF16_PARTIAL &&
            info->rcv_ppid != RAWRTC_SCTP_TRANSPORT_PPID_BINARY_PARTIAL;
    enum rawrtc_code error;

    // Reference buffer and copy receive info (if first)
    if (*buffer_inboundp == NULL) {
        // Reference & set buffer
        *buffer_inboundp = mem_ref(message_buffer);

        // Copy receive info
        memcpy(info_inboundp, info, sizeof(*info));

        // Complete?
        if (complete) {
            DEBUG_PRINTF("Incoming message of size %zu is already complete\n",
                         mbuf_get_left(message_buffer));
            error = RAWRTC_CODE_SUCCESS;
            goto out;
        }

        // Clear headroom (if any)
        if ((*buffer_inboundp)->pos > 0) {
            error = rawrtc_error_to_code(mbuf_shift(*buffer_inboundp, -(*buffer_inboundp)->pos));
            if (error) {
                goto out;
            }
        }

        // Skip to end (for upcoming chunks)
        mbuf_skip_to_end(*buffer_inboundp);
    }

    // Copy message into existing buffer
    error = rawrtc_error_to_code(mbuf_write_mem(
            *buffer_inboundp, mbuf_buf(message_buffer), mbuf_get_left(message_buffer)));
    if (error) {
        goto out;
    }
    DEBUG_PRINTF("Buffered incoming message chunk of size %zu\n", mbuf_get_left(message_buffer));

    // Stop (if not last message)
    if (!complete) {
        error = RAWRTC_CODE_NO_VALUE;
        goto out;
    }

    // Set position & done
    mbuf_set_pos(*buffer_inboundp, 0);
    DEBUG_PRINTF("Merged incoming message chunks to size %zu\n", mbuf_get_left(*buffer_inboundp));
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        // Discard the message
        *buffer_inboundp = mem_deref(*buffer_inboundp);
    }
    return error;
}

/*
 * Handle incoming application data messages.
 */
static void handle_application_message(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct mbuf* const buffer, // not checked
        struct sctp_rcvinfo* info, // not checked
        int const flags
) {
    enum rawrtc_code error;
    struct rawrtc_sctp_data_channel_context* context = NULL;
    enum rawrtc_data_channel_message_flag message_flags = RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_NONE;

    // Get channel and context
    struct rawrtc_data_channel* const channel = transport->channels[info->rcv_sid];
    if (!channel) {
        DEBUG_WARNING("Received application message on an invalid channel with SID %"PRIu16"\n",
                      info->rcv_sid);
        error = RAWRTC_CODE_INVALID_MESSAGE;
        goto out;
    }
    context = channel->transport_arg;

    // Messages may now be sent unordered
    // TODO: Should we update this flag before or after the message has been received completely
    //       (EOR)? Guessing: Once first chunk has been received.
    context->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED;

    // Handle empty / Buffer if partial delivery is off / deliver directly
    if (info->rcv_ppid == RAWRTC_SCTP_TRANSPORT_PPID_UTF16_EMPTY ||
            info->rcv_ppid == RAWRTC_SCTP_TRANSPORT_PPID_BINARY_EMPTY) {
        // Incomplete empty message?
        if (flags & SCTP_EOR) {
            DEBUG_WARNING("Empty but incomplete message, WTF are you doing?\n");
            error = RAWRTC_CODE_INVALID_MESSAGE;
            goto out;
        }

        // Reference (because we un-reference at the end and copy info)
        context->buffer_inbound = mem_ref(buffer);

        // Let the buffer appear to be empty
        mbuf_skip_to_end(context->buffer_inbound);

        // Empty message is complete
        message_flags |= RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_COMPLETE;

    } else if (!channel->options->deliver_partially) {
        // Buffer message (if needed) and get complete message (if any)
        error = buffer_message_received_raise_complete(
                &context->buffer_inbound, &context->info_inbound,
                buffer, info, flags);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                break;
            case RAWRTC_CODE_NO_VALUE:
                // Message buffered, early return here
                return;
            default:
                DEBUG_WARNING("Could not buffer/complete application message, reason: %s\n",
                              rawrtc_code_to_str(error));
                goto out;
                break;
        }

        // Update info pointer
        info = &context->info_inbound;

        // Message is complete
        message_flags |= RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_COMPLETE;
    } else {
        // Partial delivery on, pass buffer directly
        context->buffer_inbound = mem_ref(buffer);

        // Complete?
        if (flags & MSG_EOR) {
            message_flags |= RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_COMPLETE;
        }
    }

    // Handle application message
    switch (info->rcv_ppid) {
        case RAWRTC_SCTP_TRANSPORT_PPID_UTF16:
        case RAWRTC_SCTP_TRANSPORT_PPID_UTF16_EMPTY:
        case RAWRTC_SCTP_TRANSPORT_PPID_UTF16_PARTIAL:
            break;
        case RAWRTC_SCTP_TRANSPORT_PPID_BINARY:
        case RAWRTC_SCTP_TRANSPORT_PPID_BINARY_EMPTY:
        case RAWRTC_SCTP_TRANSPORT_PPID_BINARY_PARTIAL:
            message_flags |= RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_BINARY;
            break;
        default:
            DEBUG_WARNING("Ignored incoming message with unknown PPID: %"PRIu32"\n",
                          info->rcv_ppid);
            error = RAWRTC_CODE_INVALID_MESSAGE;
            goto out;
            break;
    }

    // Pass message to handler
    if (channel->message_handler) {
        channel->message_handler(context->buffer_inbound, message_flags, channel->arg);
    } else {
        DEBUG_NOTICE("No message handler, message of %zu bytes has been discarded\n",
                      mbuf_get_left(context->buffer_inbound));
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        DEBUG_WARNING("Unable to handle application message, reason: %s\n",
                      rawrtc_code_to_str(error));

        // TODO: Reset stream with SID
    }

    // Un-reference
    if (context) {
        context->buffer_inbound = mem_deref(context->buffer_inbound);
    }
}

/*
 * Handle incoming DCEP control message.
 */
static void handle_dcep_message(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct mbuf* const buffer, // not checked
        struct sctp_rcvinfo* info, // not checked
        int const flags
) {
    enum rawrtc_code error;

    // Buffer message (if needed) and get complete message (if any)
    error = buffer_message_received_raise_complete(
            &transport->buffer_dcep_inbound, &transport->info_dcep_inbound,
            buffer, info, flags);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            break;
        case RAWRTC_CODE_NO_VALUE:
            // Message buffered, early return here
            return;
        default:
            DEBUG_WARNING("Could not buffer/complete DCEP message, reason: %s\n",
                          rawrtc_code_to_str(error));
            goto out;
            break;
    }

    // Update info pointer
    info = &transport->info_dcep_inbound;

    // Handle by message type
    // Note: There MUST be at least a byte present in the buffer as SCTP cannot handle empty
    //       messages.
    uint_fast16_t const message_type = mbuf_read_u8(transport->buffer_dcep_inbound);
    switch (message_type) {
        case RAWRTC_DCEP_MESSAGE_TYPE_ACK:
            DEBUG_PRINTF("Received data channel ack message for channel with SID %"PRIu16"\n",
                         info->rcv_sid);
            handle_data_channel_ack_message(transport, info);
            break;
        case RAWRTC_DCEP_MESSAGE_TYPE_OPEN:
            DEBUG_PRINTF("Received data channel open message for channel with SID %"PRIu16"\n",
                         info->rcv_sid);
            handle_data_channel_open_message(transport, transport->buffer_dcep_inbound, info);
            break;
        default:
            DEBUG_WARNING("Ignored incoming DCEP control message with unknown type: %"PRIu16"\n",
                          message_type);
            break;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        DEBUG_WARNING("Unable to handle DCEP message, reason: %s\n", rawrtc_code_to_str(error));

        // TODO: Close channel?
    }

    // Un-reference
    transport->buffer_dcep_inbound = mem_deref(transport->buffer_dcep_inbound);
}

/*
 * Handle incoming data message.
 */
static void data_receive_handler(
        struct rawrtc_sctp_transport* const transport,
        struct mbuf* const buffer,
        struct sctp_rcvinfo* const info,
        int const flags
) {
    // Convert PPID first
    info->rcv_ppid = ntohl(info->rcv_ppid);
    DEBUG_PRINTF("Received message with SID %"PRIu16", PPID: %"PRIu32"\n",
                 info->rcv_sid, info->rcv_ppid);

    // Handle by PPID
    if (info->rcv_ppid == RAWRTC_SCTP_TRANSPORT_PPID_DCEP) {
        handle_dcep_message(transport, buffer, info, flags);
    } else {
        handle_application_message(transport, buffer, info, flags);
    }
}

/*
 * Handle usrsctp read event.
 */
static int read_event_handler(
        struct rawrtc_sctp_transport* const transport // not checked
) {
    struct mbuf* buffer;
    ssize_t length;
    int ignore_events = RAWRTC_SCTP_EVENT_NONE;
    struct sctp_rcvinfo info = {0};
    socklen_t info_length = sizeof(info);
    unsigned int info_type = 0;
    int flags = 0;

    // Closed?
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_NOTICE("Ignoring read event, transport is closed\n");
        return RAWRTC_SCTP_EVENT_ALL;
    }

    // TODO: Get next message size
    // TODO: Can we get the COMPLETE message size or just the current message size?

    // Create buffer
    buffer = mbuf_alloc(rawrtc_global.usrsctp_chunk_size);
    if (!buffer) {
        DEBUG_WARNING("Cannot allocate buffer, no memory");
        // TODO: This needs to be handled in a better way, otherwise it's probably going
        // to cause another read call which calls this handler again resulting in an infinite
        // loop.
        return RAWRTC_SCTP_EVENT_NONE;
    }

    // Receive notification or data
    length = usrsctp_recvv(
            transport->socket, buffer->buf, buffer->size, NULL, NULL,
            &info, &info_length, &info_type, &flags);
    if (length < 0) {
        // Meh...
        if (errno == EAGAIN) {
//            DEBUG_NOTICE("@ruengeler: usrsctp raised a read event but returned EAGAIN\n");
            ignore_events = SCTP_EVENT_READ;
            goto out;
        }

        // Handle error
        DEBUG_WARNING("SCTP receive failed, reason: %m\n", errno);
        // TODO: What now? Close?
        goto out;
    }

    // Update buffer position and end
    mbuf_set_end(buffer, (size_t) length);

    // Handle notification
    if (flags & MSG_NOTIFICATION) {
        handle_notification(transport, buffer);
        goto out;
    }

    // Check state
    if (transport->state != RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        DEBUG_WARNING("Ignored incoming data before state 'connected'\n");
        goto out;
    }

    // Have info?
    if (info_type != SCTP_RECVV_RCVINFO) {
        DEBUG_WARNING("Cannot handle incoming data without SCTP rcvfinfo\n");
        goto out;
    }

    // Pass data to handler
    data_receive_handler(transport, buffer, &info, flags);

out:
    // Un-reference
    mem_deref(buffer);

    // Done
    return ignore_events;
}

/*
 * Handle usrsctp write event.
 */
static int write_event_handler(
        struct rawrtc_sctp_transport* const transport // not checked
) {
    // Closed?
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_NOTICE("Ignoring write event, transport is closed\n");
        return RAWRTC_SCTP_EVENT_ALL;
    }

    // Send all deferred messages (if not already sending)
    // TODO: Check if this flag is really necessary
    if (!(transport->flags & RAWRTC_SCTP_TRANSPORT_FLAGS_SENDING_IN_PROGRESS)) {
        enum rawrtc_code error;

        // Send
        transport->flags |= RAWRTC_SCTP_TRANSPORT_FLAGS_SENDING_IN_PROGRESS;
        error = sctp_send_deferred_messages(transport);
        transport->flags &= ~RAWRTC_SCTP_TRANSPORT_FLAGS_SENDING_IN_PROGRESS;
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
            case RAWRTC_CODE_STOP_ITERATION:
                // We either sent all pending messages or could not send all messages, so there's
                // no reason to react to further write events in this iteration
                return SCTP_EVENT_WRITE;
            default:
                // TODO: What now? Close?
                DEBUG_WARNING("Could not send deferred messages, reason: %s\n",
                              rawrtc_code_to_str(error));
                return SCTP_EVENT_WRITE;
        }
    } else {
        DEBUG_WARNING("Sending still in progress!\n");
        // TODO: Is this correct?
        return SCTP_EVENT_WRITE;
    }
}

/*
 * Handle usrsctp error event.
 */
static bool error_event_handler(
        struct rawrtc_sctp_transport* const transport // not checked
) {
    // Closed?
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        DEBUG_NOTICE("Ignoring error event, transport is closed\n");
        return RAWRTC_SCTP_EVENT_ALL;
    }

    // TODO: What am I supposed to do with this information?
    DEBUG_WARNING("TODO: Handle SCTP error event\n");

    // Continue handling events
    // TODO: Probably depends on the error, right?
    return RAWRTC_SCTP_EVENT_NONE;
}

/*
 * usrsctp event handler helper.
 */
static void upcall_handler_helper(
        struct socket* socket,
        void* arg,
        int flags
) {
    int events = usrsctp_get_events(socket);
    struct rawrtc_sctp_transport* const transport = arg;
    int ignore_events = RAWRTC_SCTP_EVENT_NONE;
    (void) flags; // TODO: What does this indicate?

    // Lock event loop mutex
    rawrtc_thread_enter();

    // TODO: This loop may lead to long blocking and is unfair to normal fds.
    //       It's a compromise because scheduling repetitive timers in re's event loop seems to
    //       be slow.
    while (events) {
        // TODO: This should work but it doesn't because usrsctp keeps switching from read to write
        //       events endlessly for some reason. So, we need to discard previous events.
        //ignore_events = RAWRTC_SCTP_EVENT_NONE;

        // Handle error event
        if (events & SCTP_EVENT_ERROR) {
            ignore_events |= error_event_handler(transport);
        }

        // Handle read event
        if (events & SCTP_EVENT_READ) {
            ignore_events |= read_event_handler(transport);
        }

        // Handle write event
        if (events & SCTP_EVENT_WRITE) {
            ignore_events |= write_event_handler(transport);
        }

        // Get upcoming events and remove events that should be ignored
        events = usrsctp_get_events(socket) & ~ignore_events;
    }

    // Unlock event loop mutex
    rawrtc_thread_leave();
}

/*
 * Handle SCTP timer tick.
 */
static void timer_handler(
        void* arg
) {
    (void) arg;

    // Restart timer
    tmr_start(&rawrtc_global.usrsctp_tick_timer, RAWRTC_SCTP_TRANSPORT_TIMER_TIMEOUT,
              timer_handler, NULL);

    // Pass delta ms to usrsctp
    usrsctp_handle_timers(RAWRTC_SCTP_TRANSPORT_TIMER_TIMEOUT);
}

/*
 * Handle incoming DTLS messages.
 */
static void dtls_receive_handler(
        struct mbuf* const buffer,
        void* const arg
) {
    struct rawrtc_sctp_transport* const transport = arg;
    size_t const length = mbuf_get_left(buffer);

    // Closed?
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
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
 * Destructor for an existing SCTP data channel array.
 */
static void data_channels_destroy(
        void* arg
) {
    struct rawrtc_sctp_transport* const transport = arg;
    uint_fast16_t i;

    // Un-reference all members
    for (i = 0; i < transport->n_channels; ++i) {
        mem_deref(transport->channels[i]);
    }
}

/*
 * Create SCTP data channel array.
 *
 * Warning: Will not pre-fill stream IDs of the members!
 */
enum rawrtc_code data_channels_alloc(
        struct rawrtc_data_channel*** channelsp, // de-referenced
        uint_fast16_t const n_channels,
        uint_fast16_t const n_channels_previously
) {
    size_t i;
    struct rawrtc_data_channel** channels;

    // Check arguments
    if (!channelsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocated before and #channels is decreasing?
    if (n_channels_previously > 0 && n_channels < n_channels_previously) {
        // Ensure we're not removing active data channels
        for (i = 0; i < n_channels_previously; ++i) {
            if ((*channelsp)[i]) {
                return RAWRTC_CODE_STILL_IN_USE;
            }
        }
    }

    // Allocate
    channels = mem_reallocarray(*channelsp, n_channels, sizeof(*channels), data_channels_destroy);
    if (!channels) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Initialise
    // Note: We can safely multiply 'n_channels' with size of the struct as 'mem_reallocarray'
    //       ensures that it does not overflow (returns NULL).
    if (n_channels > n_channels_previously) {
        struct rawrtc_data_channel** channels_offset = channels + n_channels_previously;
        memset(channels_offset, 0, (n_channels - n_channels_previously) * sizeof(*channels));
    }

    // Set pointer & done
    *channelsp = channels;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing ICE transport.
 */
static void rawrtc_sctp_transport_destroy(
        void* arg
) {
    struct rawrtc_sctp_transport* const transport = arg;

    // Stop transport
    // TODO: Check effects in case transport has been destroyed due to error in create
    rawrtc_sctp_transport_stop(transport);

    // Un-reference
    mem_deref(transport->channels);
    mem_deref(transport->buffer_dcep_inbound);
    list_flush(&transport->buffered_messages_outgoing);
    mem_deref(transport->dtls_transport);

    // Decrease in-use counter
    --rawrtc_global.usrsctp_initialized;

    // Close usrsctp (if needed)
    if (rawrtc_global.usrsctp_initialized == 0) {
        // Cancel timer
        tmr_cancel(&rawrtc_global.usrsctp_tick_timer);

        // Close
        usrsctp_finish();
        DEBUG_PRINTF("Closed usrsctp\n");
    }
}

/*
 * Create an SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_create(
        struct rawrtc_sctp_transport** const transportp, // de-referenced
        struct rawrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t port, // zeroable
        rawrtc_data_channel_handler* const data_channel_handler, // nullable
        rawrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    uint_fast16_t n_channels;
    bool have_data_transport;
    struct rawrtc_sctp_transport* transport;
    struct sctp_assoc_value av;
    struct linger linger_option;
    struct sctp_event sctp_event = {0};
    size_t i;
    int option_value;
    struct sockaddr_conn peer = {0};

    // Check arguments
    if (!transportp || !dtls_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check DTLS transport state
    if (dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CLOSED
            || dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_FAILED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Set number of channels
    // TODO: Get from config
    n_channels = RAWRTC_SCTP_TRANSPORT_DEFAULT_NUMBER_OF_STREAMS;

    // Set default port (if 0)
    if (port == 0) {
        port = RAWRTC_SCTP_TRANSPORT_DEFAULT_PORT;
    }

    // Check if a data transport is already registered
    error = rawrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Initialise usrsctp (if needed)
    if (rawrtc_global.usrsctp_initialized == 0) {
        DEBUG_PRINTF("Initialising usrsctp\n");
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
        usrsctp_sysctl_set_sctp_nr_incoming_streams_default((uint32_t) n_channels);

        // Set amount of outgoing streams
        usrsctp_sysctl_set_sctp_nr_outgoing_streams_default((uint32_t) n_channels);

        // Enable interleaving messages for different streams (incoming)
        // See: https://tools.ietf.org/html/rfc6458#section-8.1.20
        usrsctp_sysctl_set_sctp_default_frag_interleave(2);

        // Start timers
        tmr_init(&rawrtc_global.usrsctp_tick_timer);
        tmr_start(&rawrtc_global.usrsctp_tick_timer, RAWRTC_SCTP_TRANSPORT_TIMER_TIMEOUT,
                  timer_handler, NULL);
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), rawrtc_sctp_transport_destroy);
    if (!transport) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Increase in-use counter
    // Note: This needs to be below allocation to ensure the counter is decreased properly on error
    ++rawrtc_global.usrsctp_initialized;

    // Set fields/reference
    transport->state = RAWRTC_SCTP_TRANSPORT_STATE_NEW; // TODO: Raise state (delayed)?
    transport->port = port;
    transport->dtls_transport = mem_ref(dtls_transport);
    transport->data_channel_handler = data_channel_handler;
    transport->state_change_handler = state_change_handler;
    transport->arg = arg;
    list_init(&transport->buffered_messages_outgoing);

    // Allocate channel array
    error = data_channels_alloc(&transport->channels, n_channels, 0);
    if (error) {
        goto out;
    }
    transport->n_channels = n_channels;
    transport->current_channel_sid = 0;

    // Create packet tracer
    // TODO: Debug mode only, filename set by debug options
#ifdef SCTP_DEBUG
    {
        char trace_handle_id[8];
        char* trace_handle_name;

        // Create trace handle ID
        rand_str(trace_handle_id, sizeof(trace_handle_id));
        error = rawrtc_sdprintf(&trace_handle_name, "trace-sctp-%s.hex", trace_handle_id);
        if (error) {
            DEBUG_WARNING("Could create trace file name, reason: %s\n", rawrtc_code_to_str(error));
        } else {
            // Open trace file
            transport->trace_handle = fopen(trace_handle_name, "w");
            mem_deref(trace_handle_name);
            if (!transport->trace_handle) {
                DEBUG_WARNING("Could not open trace file, reason: %m\n", errno);
            } else {
                DEBUG_INFO("Using trace handle id: %s\n", trace_handle_id);
            }
        }
    }
#endif

    // Create SCTP socket
    DEBUG_PRINTF("Creating SCTP socket\n");
    transport->socket = usrsctp_socket(
            AF_CONN, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
    if (!transport->socket) {
        DEBUG_WARNING("Could not create socket, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Register instance
    usrsctp_register_address(transport);

    // Make socket non-blocking
    if (usrsctp_set_non_blocking(transport->socket, 1)) {
        DEBUG_WARNING("Could not set to non-blocking, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Set event callback
    if (usrsctp_set_upcall(transport->socket, upcall_handler_helper, transport)) {
        DEBUG_WARNING("Could not set event callback (upcall), reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Determine chunk size
    if (rawrtc_global.usrsctp_initialized == 1) {
        socklen_t option_size = sizeof(int); // PD point is int according to spec
        if (usrsctp_getsockopt(
                transport->socket, IPPROTO_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
                &option_value, &option_size)) {
            DEBUG_WARNING("Could not retrieve partial delivery point, reason: %m\n", errno);
            error = rawrtc_error_to_code(errno);
            goto out;
        }

        // Check value
        if (option_size != sizeof(int) || option_value < 1) {
            DEBUG_WARNING("Invalid partial delivery point value: %d\n", option_value);
            error = RAWRTC_CODE_INITIALISE_FAIL;
            goto out;
        }

        // Store value
        rawrtc_global.usrsctp_chunk_size = (size_t) option_value;
        DEBUG_PRINTF("Chunk size: %zu\n", rawrtc_global.usrsctp_chunk_size);
    }

    // Enable the Stream Reconfiguration extension
    av.assoc_id = SCTP_ALL_ASSOC;
    av.assoc_value = SCTP_ENABLE_RESET_STREAM_REQ | SCTP_ENABLE_CHANGE_ASSOC_REQ;
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_ENABLE_STREAM_RESET,
                           &av, sizeof(struct sctp_assoc_value))) {
        DEBUG_WARNING("Could not enable stream reconfiguration extension, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Set MTU (1200|1280 (IPv4|IPv6) - UDP - DTLS (cipher suite dependent) - SCTP (12)
    // https://github.com/ortclib/ortclib-cpp/blob/master/ortc/cpp/ortc_SCTPTransport.cpp#L2143

    // We want info
    option_value = 1;
    if (usrsctp_setsockopt(
            transport->socket, IPPROTO_SCTP, SCTP_RECVRCVINFO,
            &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not set info option, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Enable interleaving messages for different streams (outgoing)
    // https://tools.ietf.org/html/draft-ietf-tsvwg-sctp-ndata-08#section-4.3.1

    // Discard pending packets when closing
    // (so we don't get a callback when the transport is already free'd)
    // TODO: Find a way to use graceful shutdown instead, otherwise the other peer would raise an
    // error indication (https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-6.2)
    linger_option.l_onoff = 1;
    linger_option.l_linger = 0;
    if (usrsctp_setsockopt(transport->socket, SOL_SOCKET, SO_LINGER,
                           &linger_option, sizeof(linger_option))) {
        DEBUG_WARNING("Could not set linger options, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Set no delay option (disable nagle)
    option_value = 1;
    if (usrsctp_setsockopt(transport->socket, IPPROTO_SCTP, SCTP_NODELAY,
                           &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not set no-delay, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Set explicit EOR
    option_value = 1;
    if (usrsctp_setsockopt(
            transport->socket, IPPROTO_SCTP, SCTP_EXPLICIT_EOR,
            &option_value, sizeof(option_value))) {
        DEBUG_WARNING("Could not enable explicit EOR, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
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
            error = rawrtc_error_to_code(errno);
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
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Attach to ICE transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = rawrtc_dtls_transport_set_data_transport(
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
 * Destructor for an existing data channel context.
 */
static void channel_context_destroy(
        void* arg
) {
    struct rawrtc_sctp_data_channel_context* const context = arg;

    // Un-reference
    mem_deref(context->buffer_inbound);
}

/*
 * Allocate data channel context.
 */
static enum rawrtc_code channel_context_create(
        struct rawrtc_sctp_data_channel_context** const contextp, // de-referenced, not checked
        uint16_t const sid,
        bool const can_send_unordered
) {
    // Allocate context
    struct rawrtc_sctp_data_channel_context* const context =
            mem_zalloc(sizeof(*context), channel_context_destroy);
    if (!context) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    context->sid = sid;
    if (can_send_unordered) {
        context->flags |= RAWRTC_SCTP_DATA_CHANNEL_FLAGS_CAN_SEND_UNORDERED;
    }

    // Set pointer & done
    *contextp = context;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Check if a data channel is registered in the transport.
 */
static bool channel_registered(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_data_channel* const channel // not checked
) {
    // Get context
    struct rawrtc_sctp_data_channel_context* const context = channel->transport_arg;

    // Check status
    if (transport->channels[context->sid] != channel) {
        DEBUG_WARNING("Invalid channel instance in slot. Please report this.\n");
        return false;
    } else {
        return true;
    }
}

/*
 * Register data channel on transport.
 */
static void channel_register(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_data_channel* const channel, // referenced, not checked
        struct rawrtc_sctp_data_channel_context* const context, // referenced, not checked
        bool const raise_event
) {
    // Update channel with referenced context
    channel->transport_arg = mem_ref(context);
    transport->channels[context->sid] = mem_ref(channel);

    // Raise data channel event?
    if (raise_event) {
        // Call data channel handler (if any)
        rawrtc_data_channel_call_channel_handler(
                channel, transport->data_channel_handler, transport->arg);
    }

    // Update data channel state
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_OPEN);
    }
}

/*
 * Create a negotiated SCTP data channel.
 */
static enum rawrtc_code channel_create_negotiated(
        struct rawrtc_sctp_data_channel_context** const contextp, // de-referenced, not checked
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_data_channel_parameters const * const parameters // read-only
) {
    // Check SID (> max, >= n_channels, or channel already occupied)
    if (parameters->id > RAWRTC_SCTP_TRANSPORT_SID_MAX ||
        parameters->id >= transport->n_channels ||
        transport->channels[parameters->id]) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate context to be used as an argument for the data channel handlers
    // TODO: Is it okay to already allow sending unordered messages here? Assuming: Yes.
    return channel_context_create(contextp, parameters->id, true);
}

/*
 * Create an SCTP data channel that needs negotiation.
 */
static enum rawrtc_code channel_create_inband(
        struct rawrtc_sctp_data_channel_context** const contextp, // de-referenced, not checked
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_data_channel_parameters const * const parameters // read-only
) {
    enum rawrtc_code error;
    uint_fast16_t i;
    struct rawrtc_sctp_data_channel_context* context;
    struct mbuf* buffer;

    // Check DTLS state
    // Note: We need to have an open DTLS connection to determine whether we use odd or even
    // SIDs.
    // TODO: Can we fix this somehow to make it possible to create data channels earlier?
    if (transport->dtls_transport->state != RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Use odd or even SIDs
    switch (transport->dtls_transport->role) {
        case RAWRTC_DTLS_ROLE_CLIENT:
            i = 0;
            break;
        case RAWRTC_DTLS_ROLE_SERVER:
            i = 1;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // Find free SID
    context = NULL;
    for (; i < transport->n_channels; i += 2) {
        if (!transport->channels[i]) {
            // Allocate context to be used as an argument for the data channel handlers
            error = channel_context_create(&context, (uint16_t) i, false);
            if (error) {
                return error;
            }
            break;
        }
    }
    if (!context) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Create open message
    buffer = NULL;
    error = data_channel_open_message_create(&buffer, parameters);
    if (error) {
        goto out;
    }

    // Send message
    DEBUG_PRINTF("Sending data channel open message for channel with SID %"PRIu16"\n",
                 context->sid);
    error = send_message(transport, NULL, context, buffer, RAWRTC_SCTP_TRANSPORT_PPID_DCEP);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(buffer);

    if (error) {
        mem_deref(context);
    } else {
        // Set pointer
        *contextp = context;
    }
    return error;
}

/*
 * Create the SCTP data channel.
 */
static enum rawrtc_code channel_create_handler(
        struct rawrtc_data_transport* const transport,
        struct rawrtc_data_channel* const channel, // referenced
        struct rawrtc_data_channel_parameters const * const parameters // read-only
) {
    struct rawrtc_sctp_transport* sctp_transport;
    enum rawrtc_code error;
    struct rawrtc_sctp_data_channel_context* context;

    // Check arguments
    if (!transport || !channel || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check if closed?

    // Get SCTP transport
    sctp_transport = transport->transport;

    // Create negotiated or in-band data channel
    if (parameters->negotiated) {
        error = channel_create_negotiated(&context, sctp_transport, parameters);
    } else {
        error = channel_create_inband(&context, sctp_transport, parameters);
    }
    if (error) {
        return error;
    }

    // Register data channel
    channel_register(sctp_transport, channel, context, false);

    // Un-reference & done
    mem_deref(context);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Close the data channel (transport handler).
 */
static enum rawrtc_code channel_close_handler(
        struct rawrtc_data_channel* const channel
) {
    struct rawrtc_sctp_transport* transport;
    struct rawrtc_sctp_data_channel_context* context;

    // Check arguments
    if (!channel) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check if closed?

    // Get SCTP transport & context
    transport = channel->transport->transport;
    context = channel->transport_arg;

    // Un-reference channel and clear pointer (if channel was registered before)
    // Note: The context will be NULL if the channel was not registered before
    if (context) {
        DEBUG_PRINTF("Closing channel with SID %"PRIu16"\n", context->sid);

        // Sanity check
        if (!channel_registered(transport, channel)) {
            return RAWRTC_CODE_UNKNOWN_ERROR;
        }

        // Reset outgoing streams
        // Important: This function will change the state of the channel to CLOSED
        //            and remove the channel from the transport on error.
        if (!reset_outgoing_stream(transport, channel)) {
            rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSING);
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Send data via the data channel (transport handler).
 */
static enum rawrtc_code channel_send_handler(
        struct rawrtc_data_channel* const channel,
        struct mbuf* buffer, // nullable (if size 0), referenced
        bool const is_binary
) {
    struct rawrtc_sctp_transport* transport;
    size_t length;
    uint_fast32_t ppid;
    struct mbuf* empty = NULL;
    enum rawrtc_code error;

    // Check arguments
    if (!channel) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check if closed?

    // Get SCTP transport
    transport = channel->transport->transport;

    // We accept both a NULL buffer and a buffer of length 0
    if (!buffer) {
        length = 0;
    } else {
        length = mbuf_get_left(buffer);
    }

    // Empty message?
    if (length == 0) {
        // Set PPID
        if (is_binary) {
            ppid = RAWRTC_SCTP_TRANSPORT_PPID_BINARY_EMPTY;
        } else {
            ppid = RAWRTC_SCTP_TRANSPORT_PPID_UTF16_EMPTY;
        }

        // Create helper message as SCTP is unable to send messages of size 0
        empty = mbuf_alloc(RAWRTC_SCTP_TRANSPORT_EMPTY_MESSAGE_SIZE);
        if (!empty) {
            return RAWRTC_CODE_NO_MEMORY;
        }

        // Note: The content is being ignored
        error = rawrtc_error_to_code(mbuf_write_u8(empty, 0));
        if (error) {
            goto out;
        }

        // Set position & pointer
        mbuf_set_pos(empty, 0);
        buffer = empty;
    } else {
        // Check size
        if (transport->remote_maximum_message_size != 0 &&
            length > transport->remote_maximum_message_size) {
            return RAWRTC_CODE_MESSAGE_TOO_LONG;
        }

        // Set PPID
        // Note: We will not use the deprecated fragmentation & reassembly
        if (is_binary) {
            ppid = RAWRTC_SCTP_TRANSPORT_PPID_BINARY;
        } else {
            ppid = RAWRTC_SCTP_TRANSPORT_PPID_UTF16;
        }
    }

    // Send
    error = send_message(transport, channel, channel->transport_arg, buffer, ppid);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(empty);

    // Done
    return error;
}

/*
 * Get the SCTP data transport instance.
 */
enum rawrtc_code rawrtc_sctp_transport_get_data_transport(
        struct rawrtc_data_transport** const transportp, // de-referenced
        struct rawrtc_sctp_transport* const sctp_transport // referenced
) {
    enum rawrtc_code error;

    // Check arguments
    if (!sctp_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check SCTP transport state
    if (sctp_transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Lazy-create data transport
    if (!sctp_transport->data_transport) {
        error = rawrtc_data_transport_create(
                &sctp_transport->data_transport, RAWRTC_DATA_TRANSPORT_TYPE_SCTP, sctp_transport,
                channel_create_handler, channel_close_handler, channel_send_handler);
        if (error) {
            return error;
        }
    } else {
        // +1 when handing out the instance
        mem_ref(sctp_transport->data_transport);
    }

    // Set pointer & done
    *transportp = sctp_transport->data_transport;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Start the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_start(
        struct rawrtc_sctp_transport* const transport,
        struct rawrtc_sctp_capabilities const * const remote_capabilities, // copied
        uint16_t remote_port // zeroable
) {
    struct sockaddr_conn peer = {0};
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!transport || !remote_capabilities) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state != RAWRTC_SCTP_TRANSPORT_STATE_NEW) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Set default port (if 0)
    if (remote_port == 0) {
        remote_port = transport->port;
    }

    // Store maximum message size
    transport->remote_maximum_message_size = remote_capabilities->max_message_size;

    // Set remote address
    peer.sconn_family = AF_CONN;
    // TODO: Check for existance of sconn_len
    //sconn.sconn_len = sizeof(peer);
    peer.sconn_port = htons(remote_port);
    peer.sconn_addr = transport;

    // Connect
    DEBUG_PRINTF("Connecting to peer\n");
    if (usrsctp_connect(transport->socket, (struct sockaddr*) &peer, sizeof(peer)) &&
            errno != EINPROGRESS) {
        DEBUG_WARNING("Could not connect, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Initiate Path MTU discovery (https://tools.ietf.org/html/rfc4821)
    // by using probing messages (https://tools.ietf.org/html/rfc4820)
    // see https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-5

    // Transition to connecting state
    set_state(transport, RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING);

out:
    if (error) {
        set_state(transport, RAWRTC_SCTP_TRANSPORT_STATE_CLOSED);
    }
    return error;
}


/*
 * Stop and close the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_stop(
        struct rawrtc_sctp_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Update state
    set_state(transport, RAWRTC_SCTP_TRANSPORT_STATE_CLOSED);
    return RAWRTC_CODE_SUCCESS;

    // TODO: Anything missing?
}

/*
 * Create outgoing message context for buffering SCTP messages.
 */
enum rawrtc_code message_send_context_create(
        struct send_context** const contextp, // de-referenced, not checked
        void* const info, // not checked
        unsigned int const info_type,
        int const flags
) {
    enum rawrtc_code error;
    struct send_context* context;

    // Allocate context
    context = mem_zalloc(sizeof(*context), NULL);
    if (!context) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set context fields
    context->info_type = info_type;
    context->flags = flags;

    // Copy info data (if any)
    if (info_type != SCTP_SENDV_NOINFO && info) {
        // Copy info data according to type
        // Note: info_size will be ignored for buffered messages
        switch (info_type) {
            case SCTP_SENDV_SNDINFO:
                memcpy(&context->info.sndinfo, info, sizeof(context->info.sndinfo));
                break;
            case SCTP_SENDV_SPA:
                memcpy(&context->info.spa, info, sizeof(context->info.spa));
                break;
            default:
                error = RAWRTC_CODE_INVALID_STATE;
                goto out;
        }
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(context);
    } else {
        // Set pointer
        *contextp = context;
    }

    return error;
}

/*
 * Send a message (non-deferred) via the SCTP transport.
 */
enum rawrtc_code sctp_transport_send(
        struct rawrtc_sctp_transport* const transport, // not checked
        struct mbuf* const buffer, // not checked
        void* const info, // not checked
        socklen_t const info_size,
        unsigned int const info_type,
        int const flags
) {
    struct sctp_sndinfo* send_info;
    bool eor_set;
    size_t length;
    ssize_t written;
    enum rawrtc_code error;

    // Check state
    if (transport->state != RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Get reference to send flags
    switch (info_type) {
        case SCTP_SENDV_SNDINFO:
            send_info = (struct sctp_sndinfo* const) info;
            break;
        case SCTP_SENDV_SPA:
            send_info = &((struct sctp_sendv_spa* const) info)->sendv_sndinfo;
            break;
        default:
            return RAWRTC_CODE_INVALID_STATE;
    }

    // EOR set?
    eor_set = send_info->snd_flags & SCTP_EOR ? true : false;

    // Send until buffer is empty
    do {
        size_t const left = mbuf_get_left(buffer);

        // Carefully chunk the buffer
        if (left > rawrtc_global.usrsctp_chunk_size) {
            length = rawrtc_global.usrsctp_chunk_size;

            // Unset EOR flag
            send_info->snd_flags &= ~SCTP_EOR;
        } else {
            length = left;

            // Reset EOR flag
            if (eor_set) {
                send_info->snd_flags |= SCTP_EOR;
            }
        }

        // Send
        DEBUG_PRINTF("Try sending %zu/%zu bytes\n", length, left);
        written = usrsctp_sendv(
                transport->socket, mbuf_buf(buffer), length, NULL, 0,
                info, info_size, info_type, flags);
#ifdef SCTP_DEBUG
        DEBUG_PRINTF("usrsctp_sendv(socket=%p, buffer=%p, length=%zu/%zu, info={sid: %"PRIu16", "
                     "ppid: %"PRIu32", eor: %s (was %s}) -> %zd (errno: %m)\n",
                     transport->socket, mbuf_buf(buffer), length, left, send_info->snd_sid,
                     ntohl(send_info->snd_ppid),
                     send_info->snd_flags & SCTP_EOR ? "true" : "false",
                     eor_set ? "true" : "false",
                     written, errno);
#endif
        if (written < 0) {
            error = rawrtc_error_to_code(errno);
            goto out;
        }

        // TODO: Remove
        if (written == 0) {
            DEBUG_NOTICE("@tuexen: usrsctp_sendv returned 0\n");
            error = RAWRTC_CODE_TRY_AGAIN_LATER;
            goto out;
        }

        // If not all bytes have been written, this obviously means that usrsctp's buffer is full
        // and we need to try again later.
        if (written < length) {
            // TODO: Comment in and remove section above
//            error = RAWRTC_CODE_TRY_AGAIN_LATER;
//            goto out;
        }

        // Update buffer position
        mbuf_advance(buffer, written);
    } while (mbuf_get_left(buffer) > 0);

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    // Reset EOR flag
    if (eor_set) {
        send_info->snd_flags |= SCTP_EOR;
    }

    return error;
}

/*
 * Send a message via the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_send(
        struct rawrtc_sctp_transport* const transport,
        struct mbuf* const buffer,
        void* const info,
        socklen_t const info_size,
        unsigned int const info_type,
        int const flags
) {
    struct send_context* context;
    enum rawrtc_code error;

    // Check arguments
    if (!transport || !buffer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Clear buffered amount low flag
    transport->flags &= ~RAWRTC_SCTP_TRANSPORT_FLAGS_BUFFERED_AMOUNT_LOW;

    // Send directly (if connected and no outstanding messages)
    if (transport->state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED &&
            list_isempty(&transport->buffered_messages_outgoing)) {
        // Try sending
        DEBUG_PRINTF("Message queue is empty, sending directly\n");
        error = sctp_transport_send(
                transport, buffer, info, info_size, info_type, flags);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                // Done
                return RAWRTC_CODE_SUCCESS;
            case RAWRTC_CODE_TRY_AGAIN_LATER:
                DEBUG_PRINTF("Need to buffer message and wait for a write request\n");
                break;
            case RAWRTC_CODE_MESSAGE_TOO_LONG:
                DEBUG_WARNING("Incorrect message size guess, report this!\n");
                return error;
            default:
                return error;
        }
    }

    // Create message context (for buffering)
    error = message_send_context_create(&context, info, info_type, flags);
    if (error) {
        goto out;
    }

    // Buffer message
    error = rawrtc_message_buffer_append(&transport->buffered_messages_outgoing, buffer, context);
    if (error) {
        goto out;
    }
    DEBUG_PRINTF("Buffered outgoing message of size %zu\n", mbuf_get_left(buffer));

out:
    // Un-reference
    mem_deref(context);

    return error;
}

/*
 * Get the local port of the SCTP transport.
 */
enum rawrtc_code rawrtc_sctp_transport_get_port(
        uint16_t* const portp, // de-referenced
        struct rawrtc_sctp_transport* const transport
) {
    // Check arguments
    if (!portp || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    *portp = transport->port;

    // Done
    return RAWRTC_CODE_SUCCESS;
}
