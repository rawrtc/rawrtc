#pragma once
#include <rawrtc.h>

/*
 * ICE server type.
 * Note: Update `ice_server_schemes` if changed.
 */
enum rawrtc_ice_server_type {
    RAWRTC_ICE_SERVER_TYPE_STUN,
    RAWRTC_ICE_SERVER_TYPE_TURN
};

/*
 * ICE server transport protocol.
 */
enum rawrtc_ice_server_transport {
    RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    RAWRTC_ICE_SERVER_TRANSPORT_TCP,
    RAWRTC_ICE_SERVER_TRANSPORT_DTLS,
    RAWRTC_ICE_SERVER_TRANSPORT_TLS
};

struct rawrtc_ice_server {
    struct le le;
    struct list urls; // deep-copied
    char* username; // copied
    char* credential; // copied
    enum rawrtc_ice_credential_type credential_type;
};

/*
 * ICE server URL. (list element)
 */
struct rawrtc_ice_server_url {
    struct le le;
    char* url; // copied
    struct pl host; // points inside `url`
    enum rawrtc_ice_server_type type;
    enum rawrtc_ice_server_transport transport;
    struct sa ipv4_address;
    struct rawrtc_ice_server_url_dns_context* dns_a_context;
    struct sa ipv6_address;
    struct rawrtc_ice_server_url_dns_context* dns_aaaa_context;
};

/*
 * ICE server URL DNS resolve context.
 */
struct rawrtc_ice_server_url_dns_context {
    uint_fast16_t dns_type;
    struct rawrtc_ice_server_url* url;
    struct rawrtc_ice_gatherer* gatherer;
    struct dns_query* dns_query;
};

enum rawrtc_code rawrtc_ice_server_create(
    struct rawrtc_ice_server** const serverp, // de-referenced
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

enum rawrtc_code rawrtc_ice_server_copy(
    struct rawrtc_ice_server** const serverp, // de-referenced
    struct rawrtc_ice_server* const source_server
);

enum rawrtc_code rawrtc_ice_server_url_destroy_dns_contexts(
    struct rawrtc_ice_server_url* const url
);

enum rawrtc_code rawrtc_ice_server_destroy_dns_contexts(
    struct rawrtc_ice_server* const server
);

enum rawrtc_code rawrtc_ice_server_dns_queries_pending(
    struct rawrtc_ice_server_url** const urlp, // de-referenced
    bool* const pendingp, // de-referenced
    struct rawrtc_ice_server* const server
);

int rawrtc_ice_server_debug(
    struct re_printf* const pf,
    struct rawrtc_ice_server const* const server
);
