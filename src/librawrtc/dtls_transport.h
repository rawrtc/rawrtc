#pragma once
#include <rawrtc.h>

/*
 * Handle inbound application data.
 */
typedef void (rawrtc_dtls_transport_receive_handler)(
    struct mbuf* const buffer,
    void* const arg
);

struct rawrtc_dtls_transport {
    enum rawrtc_dtls_transport_state state;
    struct rawrtc_ice_transport* ice_transport; // referenced
    struct list certificates; // deep-copied
    rawrtc_dtls_transport_state_change_handler* state_change_handler; // nullable
    rawrtc_dtls_transport_error_handler* error_handler; // nullable
    void* arg; // nullable
    struct rawrtc_dtls_parameters* remote_parameters; // referenced
    enum rawrtc_dtls_role role;
    bool connection_established;
    struct list buffered_messages_in;
    struct list buffered_messages_out;
    struct list fingerprints;
    struct tls* context;
    struct dtls_sock* socket;
    struct tls_conn* connection;
    rawrtc_dtls_transport_receive_handler* receive_handler;
    void* receive_handler_arg;
};

enum rawrtc_code rawrtc_dtls_transport_create_internal(
    struct rawrtc_dtls_transport** const transportp, // de-referenced
    struct rawrtc_ice_transport* const ice_transport, // referenced
    struct list* certificates, // de-referenced, copied (shallow)
    rawrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
    rawrtc_dtls_transport_error_handler* const error_handler, // nullable
    void* const arg // nullable
);

enum rawrtc_code rawrtc_dtls_transport_add_candidate_pair(
    struct rawrtc_dtls_transport* const transport,
    struct ice_candpair* const candidate_pair
);

enum rawrtc_code rawrtc_dtls_transport_have_data_transport(
    bool* const have_data_transportp, // de-referenced
    struct rawrtc_dtls_transport* const transport
);

enum rawrtc_code rawrtc_dtls_transport_set_data_transport(
    struct rawrtc_dtls_transport* const transport,
    rawrtc_dtls_transport_receive_handler* const receive_handler,
    void* const arg
);

enum rawrtc_code rawrtc_dtls_transport_clear_data_transport(
    struct rawrtc_dtls_transport* const transport
);

enum rawrtc_code rawrtc_dtls_transport_send(
    struct rawrtc_dtls_transport* const transport,
    struct mbuf* const buffer
);

enum rawrtc_code rawrtc_dtls_transport_get_external_role(
    enum rawrtc_external_dtls_role* const rolep, // de-referenced
    struct rawrtc_dtls_transport* const transport
);

enum rawrtc_code rawrtc_dtls_transport_get_external_state(
    enum rawrtc_external_dtls_transport_state* const statep, // de-referenced
    struct rawrtc_dtls_transport* const transport
);
