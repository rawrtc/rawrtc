#include <time.h> // time, localtime, strftime
#include <sys/time.h> // gettimeofday
#include <stdio.h> // fopen, fprintf, fflush
#include <arpa/inet.h> // htons, htonl
#include <rawrtc.h>
#include "packet_trace.h"
#include "utils.h"

#define DEBUG_MODULE "packet-trace"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

char const path_separator =
#ifdef _WIN32
    '\\';
#else
    '/';
#endif

static char const* const layer_to_str(
        enum rawrtc_layer const layer
) {
    switch (layer) {
        case RAWRTC_LAYER_SCTP:
            return "SCTP";
        case RAWRTC_LAYER_DTLS_SRTP:
            return "DTLS-SRTP";
        case RAWRTC_LAYER_ICE_RELAY:
        case RAWRTC_LAYER_ICE_SRFLX:
        case RAWRTC_LAYER_ICE_HOST:
            return "ICE";
        case RAWRTC_LAYER_TURN:
            return "TURN";
        case RAWRTC_LAYER_STUN:
            return "STUN";
        default:
            return "???";
    }
}

/*
 * Create and open a packet trace handle.
 */
enum rawrtc_code rawrtc_packet_trace_handle_open(
        FILE** const trace_handlep, // de-referenced
        void* const instance,
        struct rawrtc_config* const config,
        enum rawrtc_layer const layer
) {
    time_t const now_utc_raw = time(NULL);
    struct tm* const now_local = localtime(&now_utc_raw);
    char now_str[20];
    enum rawrtc_code error;
    char* trace_handle_name;
    FILE* trace_handle;

    // Check arguments
    if (!trace_handlep || !config || !config->debug.packet_trace_path) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Already open?
    if (*trace_handlep) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Convert local time to string
    if (strftime(now_str, ARRAY_SIZE(now_str), "%Y-%m-%d_%H:%M:%S", now_local) == 0) {
        DEBUG_NOTICE("Could not convert local time to string, reason: Buffer too small\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create trace handle ID
    error = rawrtc_sdprintf(
            &trace_handle_name, "%s%c%s_%p_%d_%s.hex", config->debug.packet_trace_path,
            path_separator, now_str, instance, (int) layer, layer_to_str(layer));
    if (error) {
        DEBUG_NOTICE("Could create trace file name, reason: %s\n", rawrtc_code_to_str(error));
        return error;
    }

    // Open trace file
    trace_handle = fopen(trace_handle_name, "a");
    if (!trace_handle) {
        DEBUG_NOTICE("Could not open trace file, reason: %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // Set pointer & done
    DEBUG_PRINTF("Using trace file: %s\n", trace_handle_name);
    *trace_handlep = trace_handle;
    error = RAWRTC_CODE_SUCCESS;

out:
    mem_deref(trace_handle_name);
    return error;
}

/*
 * Close an existing packet trace handle.
 */
enum rawrtc_code rawrtc_packet_trace_handle_close(
        FILE* const trace_handle
) {
    // Check arguments
    if (!trace_handle) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Close trace file
    if (fclose(trace_handle)) {
        DEBUG_NOTICE("Could not close trace file, reason: %m\n", errno);
        return rawrtc_error_to_code(errno);
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Write raw binary data to a packet trace handle.
 */
enum rawrtc_code rawrtc_packet_trace_handle_dump_raw(
        FILE* const trace_handle,
        uint8_t* const data,
        size_t const length,
        enum rawrtc_packet_direction const direction,
        struct sa* const source_address, // nullable
        struct sa* const destination_address, // nullable
        enum rawrtc_transport_protocol const transport_protocol,
        bool const add_transport_protocol_header
) {
    struct timeval now_timestamp;
    struct tm* now_local;
    size_t ip_header_length = 0;
    struct mbuf* header = NULL;
    enum rawrtc_code error;
    int err;
    size_t i;

    // Check arguments
    if (!trace_handle || !data
            || (source_address && !destination_address)
            || (!source_address && destination_address)
            || (add_transport_protocol_header && (!source_address || !destination_address))) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get current time
    if (gettimeofday(&now_timestamp, NULL) == -1) {
        DEBUG_NOTICE("Unable to get current timestamp, reason %m\n", errno);
        error = rawrtc_error_to_code(errno);
        goto out;
    }
    now_local = localtime(&now_timestamp.tv_sec);
    if (!now_local) {
        DEBUG_NOTICE("Unable to convert timestamp to local time\n");
        error = RAWRTC_CODE_UNKNOWN_ERROR;
        goto out;
    }

    // Calculate headroom (for IP header if requested)
    if (source_address) {
        // Sanity-check
        if (sa_af(source_address) != sa_af(destination_address)) {
            DEBUG_NOTICE("Unable to write IP header, address family mismatch\n");
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Length depending on IP version
        ip_header_length = sa_af(source_address) == AF_INET ? 20 : 40;
    }

    // Add protocol header (if requested)
    if (add_transport_protocol_header) {
        // Create header (large enough to also fit IP header)
        // TODO: Needs to be adjusted when adding TCP
        header = mbuf_alloc(ip_header_length + 8);
        if (!header) {
            return RAWRTC_CODE_NO_MEMORY;
        }
        mbuf_set_end(header, ip_header_length);
        mbuf_skip_to_end(header);

        // Add UDP header
        switch (transport_protocol) {
            case RAWRTC_TRANSPORT_PROTOCOL_UDP:
                // Source port
                err = mbuf_write_u16(header, htons(sa_port(source_address)));

                // Destination port
                err |= mbuf_write_u16(header, htons(sa_port(destination_address)));

                // Total packet length (including UDP header)
                if ((8 + length) > UINT16_MAX) {
                    DEBUG_NOTICE("UDP packet too large to trace\n");
                    error = RAWRTC_CODE_INVALID_ARGUMENT;
                    goto out;
                }
                err |= mbuf_write_u16(header, htons((uint16_t) (8 + length)));

                // Checksum
                err |= mbuf_write_u16(header, htons(0x0000));

                // Handle error
                if (err) {
                    DEBUG_NOTICE("Unable to write UDP header, reason: %m\n", err);
                    error = rawrtc_error_to_code(err);
                    goto out;
                }
                break;

            case RAWRTC_TRANSPORT_PROTOCOL_TCP:
                // TODO: Implement
                error = RAWRTC_CODE_NOT_IMPLEMENTED;
                goto out;
                break;

            default:
                DEBUG_NOTICE("Unsupported transport protocol %d\n", transport_protocol);
                error = RAWRTC_CODE_INVALID_ARGUMENT;
                goto out;
                break;
        }
    }

    // Add IP header (if requested)
    if (source_address) {
        // Create buffer (if needed)
        uint16_t transport_header_length = 0;
        if (header) {
            transport_header_length = (uint16_t) header->pos;
            mbuf_set_pos(header, 0);
        } else {
            // Create header
            header = mbuf_alloc(ip_header_length);
            if (!header) {
                return RAWRTC_CODE_NO_MEMORY;
            }
        }

        switch (sa_af(source_address)) {
            case AF_INET:
                // Version | IHL
                err = mbuf_write_u8(header, 0x45);

                // DSCP | ECN
                err |= mbuf_write_u8(header, 0x00);

                // Total packet length (including IP and transport protocol header)
                if ((20 + transport_header_length + length) > UINT16_MAX) {
                    DEBUG_NOTICE("IPv4 packet too large to trace\n");
                    error = RAWRTC_CODE_INVALID_ARGUMENT;
                    goto out;
                }
                err |= mbuf_write_u16(
                        header, htons((uint16_t) (20 + transport_header_length + length)));

                // Identification
                err |= mbuf_write_u16(header, htons(0x0000));

                // Flags | Fragment offset
                err |= mbuf_write_u16(header, htons(0x0000));

                // TTL
                err |= mbuf_write_u8(header, 0x40);

                // Protocol
                err |= mbuf_write_u8(header, (uint8_t) transport_protocol);

                // Checksum
                err |= mbuf_write_u16(header, htons(0x0000));

                // Source address
                err |= mbuf_write_u32(header, source_address->u.in.sin_addr.s_addr);

                // Destination address
                err |= mbuf_write_u32(header, destination_address->u.in.sin_addr.s_addr);

                // Handle error
                if (err) {
                    DEBUG_NOTICE("Unable to write IPv4 header, reason: %m\n", err);
                    error = rawrtc_error_to_code(err);
                    goto out;
                }
                break;

            case AF_INET6:
                // Version | Traffic class | Flow label
                err = mbuf_write_u8(header, 0x60);
                err |= mbuf_write_u8(header, 0x00);
                err |= mbuf_write_u8(header, 0x00);
                err |= mbuf_write_u8(header, 0x00);

                // Payload length (including transport protocol header)
                if ((transport_header_length + length) > UINT16_MAX) {
                    DEBUG_NOTICE("IPv6 packet too large to trace\n");
                    error = RAWRTC_CODE_INVALID_ARGUMENT;
                    goto out;
                }
                err |= mbuf_write_u16(header, htons((uint16_t) (transport_header_length + length)));

                // Next header
                err |= mbuf_write_u8(header, (uint8_t) transport_protocol);

                // Hop limit
                err |= mbuf_write_u8(header, 0x40);

                // Source address
                sa_in6(source_address, mbuf_buf(header));
                mbuf_advance(header, 16);

                // Destination address
                sa_in6(destination_address, mbuf_buf(header));
                mbuf_advance(header, 16);

                // Handle error
                if (err) {
                    DEBUG_NOTICE("Unable to write IPv6 header, reason: %m\n", err);
                    error = rawrtc_error_to_code(err);
                    goto out;
                }
                break;

            default:
                DEBUG_NOTICE("Unsupported address family %d\n", sa_af(source_address));
                error = RAWRTC_CODE_INVALID_ARGUMENT;
                goto out;
                break;
        }
    }

    // Preamble
    err = fprintf(
            trace_handle, "%c %02d:%02d:%02d.%06ld 0000",
            direction == RAWRTC_PACKET_TRACE_INBOUND ? 'I' : 'O',
            now_local->tm_hour, now_local->tm_min, now_local->tm_sec, now_timestamp.tv_usec);
    if (err < 0) {
        DEBUG_NOTICE("Unable to write preamble from packet to trace handle\n");
        // Note: Damage is done - no way to recover.
        error = RAWRTC_CODE_SUCCESS;
        goto out;
    }

    // Header binary to hex
    if (header) {
        uint8_t* const header_ptr = header->buf;
        size_t const header_length = header->end;
        header->pos = 0;
        for (i = 0; i < header_length; ++i) {
            if (fprintf(trace_handle, " %02x", header_ptr[i]) < 0) {
                DEBUG_NOTICE("Unable to write header from packet to trace handle\n");
                // Note: Damage is done - no way to recover.
                error = RAWRTC_CODE_SUCCESS;
                goto out;
            }
        }
    }

    // Data binary to hex
    for (i = 0; i < length; ++i) {
        if (fprintf(trace_handle, " %02x", data[i]) < 0) {
            DEBUG_NOTICE("Unable to write data from packet to trace handle\n");
            // Note: Damage is done - no way to recover.
            error = RAWRTC_CODE_SUCCESS;
            goto out;
        }
    }

    // Insert new line
    if (fprintf(trace_handle, "\n") < 0) {
        DEBUG_NOTICE("Unable to write new line to trace handle\n");
        // Note: Damage is done - no way to recover.
        error = RAWRTC_CODE_SUCCESS;
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference, flush & done
    mem_deref(header);
    if (!error) {
        fflush(trace_handle);
    }
    return error;
}

/*
 * Write buffered binary data to a packet trace handle.
 */
enum rawrtc_code rawrtc_packet_trace_handle_dump(
        FILE* const trace_handle,
        struct mbuf* const buffer,
        enum rawrtc_packet_direction const direction,
        struct sa* const source_address, // nullable
        struct sa* const destination_address, // nullable
        enum rawrtc_transport_protocol const transport_protocol,
        bool const add_transport_protocol_header
) {
    // Check arguments
    // Note: Other arguments are checked in `rawrtc_packet_trace_handle_dump_raw`.
    if (!buffer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Dump raw data
    return rawrtc_packet_trace_handle_dump_raw(
            trace_handle, mbuf_buf(buffer), mbuf_get_left(buffer), direction, source_address,
            destination_address, transport_protocol, add_transport_protocol_header);
}

/*
 * Create a packet trace helper context.
 */
enum rawrtc_code rawrtc_packet_trace_helper_context_create(
        struct rawrtc_packet_trace_helper_context** const contextp, // de-referenced
        FILE* const trace_handle,
        struct sa* const local_address,
        void* const arg // nullable
) {
    struct rawrtc_packet_trace_helper_context* context;

    // Check arguments
    if (!contextp || !trace_handle) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    context = mem_zalloc(sizeof(*context), NULL);
    if (!context) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    context->trace_handle = trace_handle;
    context->local_address = *local_address;
    context->arg = arg;

    // Set pointer & done
    *contextp = context;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Handle outbound UDP data (write to packet trace handle).
 */
bool rawrtc_packet_trace_udp_outbound_handler(
        int* err,
        struct sa* destination_address,
        struct mbuf* buffer,
        void* arg
) {
    (void) err;
    struct rawrtc_packet_trace_helper_context* const context = arg;

    // Dump packet
    enum rawrtc_code const error = rawrtc_packet_trace_handle_dump(
            context->trace_handle, buffer, RAWRTC_PACKET_TRACE_INBOUND, &context->local_address,
            destination_address, RAWRTC_TRANSPORT_PROTOCOL_UDP, true);
    if (error) {
        DEBUG_NOTICE("Unable to trace outbound packet, reason: %s\n", rawrtc_code_to_str(error));
    }

    // Not handled
    return false;
}

/*
 * Handle inbound data (write to packet trace handle).
 */
bool rawrtc_packet_trace_udp_inbound_handler(
        struct sa* source_address,
        struct mbuf* buffer,
        void* arg
) {
    struct rawrtc_packet_trace_helper_context* const context = arg;

    // Dump packet
    enum rawrtc_code const error = rawrtc_packet_trace_handle_dump(
            context->trace_handle, buffer, RAWRTC_PACKET_TRACE_OUTBOUND, source_address,
            &context->local_address, RAWRTC_TRANSPORT_PROTOCOL_UDP, true);
    if (error) {
        DEBUG_NOTICE("Unable to trace inbound packet, reason: %s\n", rawrtc_code_to_str(error));
    }

    // Not handled
    return false;
}
