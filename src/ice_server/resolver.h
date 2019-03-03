#pragma once
#include "address.h"
#include "server.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE server URL address resolved handler.
 *
 * `*resolverp` must be referenced if used.
 *
 * Return `true` if you want to continue receiving further addresses
 * from the URL's address entry. Be aware that you will be offered at
 * least one IPv4 address and one IPv6 address per URL (if available)
 * even if you always return `false`.
 */
typedef bool (*rawrtc_ice_server_url_address_resolved_handler)(
    struct rawrtc_ice_server_url_address* const address,
    void* const arg
);

/*
 * ICE server URL resolver.
 */
struct rawrtc_ice_server_url_resolver {
    struct le le;
    struct rawrtc_ice_server_url* url; // referenced
    rawrtc_ice_server_url_address_resolved_handler address_handler;
    void* arg;
    uint_fast16_t dns_type;
    struct dns_query* dns_query;
};

enum rawrtc_code rawrtc_ice_server_url_resolver_create(
    struct rawrtc_ice_server_url_resolver** const resolverp, // de-referenced
    struct dnsc* const dns_client,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_server_url* const url, // referenced
    rawrtc_ice_server_url_address_resolved_handler address_handler,
    void* const arg
);
