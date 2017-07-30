#pragma once
#include <rawrtc.h>

enum rawrtc_packet_direction {
    RAWRTC_PACKET_TRACE_INBOUND,
    RAWRTC_PACKET_TRACE_OUTBOUND
};

enum rawrtc_transport_protocol {
    RAWRTC_TRANSPORT_PROTOCOL_UDP = 0x11,
    RAWRTC_TRANSPORT_PROTOCOL_TCP = 0x06,
    RAWRTC_TRANSPORT_PROTOCOL_SCTP = 0x84
};

/*
 * Trace helper context.
 */
struct rawrtc_packet_trace_helper_context {
    struct le le;
    FILE* trace_handle;
    struct sa local_address;
    void* arg;
};

enum rawrtc_code rawrtc_packet_trace_handle_open(
    FILE** const trace_handlep, // de-referenced
    void* const instance,
    struct rawrtc_config* const config,
    enum rawrtc_layer const layer
);

enum rawrtc_code rawrtc_packet_trace_handle_close(
    FILE* const trace_handle
);

enum rawrtc_code rawrtc_packet_trace_handle_dump_raw(
    FILE* const trace_handle,
    uint8_t* const data,
    size_t const length,
    enum rawrtc_packet_direction const direction,
    struct sa* const source_address, // nullable
    struct sa* const destination_address, // nullable
    enum rawrtc_transport_protocol const transport_protocol,
    bool const add_transport_protocol_header
);

enum rawrtc_code rawrtc_packet_trace_handle_dump(
    FILE* const trace_handle,
    struct mbuf* const buffer,
    enum rawrtc_packet_direction const direction,
    struct sa* const source_address, // nullable
    struct sa* const destination_address, // nullable
    enum rawrtc_transport_protocol const transport_protocol,
    bool const add_transport_protocol_header
);

enum rawrtc_code rawrtc_packet_trace_helper_context_create(
    struct rawrtc_packet_trace_helper_context** const contextp, // de-referenced
    FILE* const trace_handle,
    struct sa* const local_address,
    void* const arg
);

bool rawrtc_packet_trace_udp_outbound_handler(
    int* err,
    struct sa* destination,
    struct mbuf* buffer,
    void* arg
);

bool rawrtc_packet_trace_udp_inbound_handler(
    struct sa* source_address,
    struct mbuf* buffer,
    void* arg
);
