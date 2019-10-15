#pragma once
#include "candidate.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE candidate mDNS hostname address resolved handler.
 *
 * `*resolverp` must be referenced if used.
 *
 * Return `true` if you want to continue receiving further addresses
 * from the URL's address entry. Be aware that you will be offered at
 * least one IPv4 address and one IPv6 address per URL (if available)
 * even if you always return `false`.
 */
typedef bool (*rawrtc_ice_candidate_mdns_address_resolved_handler)(
    struct rawrtc_ice_candidate* const candidate,
    char* const hostname,
    struct sa* const address,
    void* const arg);

/*
 * ICE candidate mDNS hostname resolver.
 */
struct rawrtc_ice_candidate_mdns_resolver {
    struct le le;
    struct rawrtc_ice_candidate* candidate;  // referenced
    char* hostname;  // copied
    rawrtc_ice_candidate_mdns_address_resolved_handler address_handler;
    void* arg;
    uint_fast16_t dns_type;
    struct dns_query* dns_query;
};

enum rawrtc_code rawrtc_ice_candidate_mdns_resolver_create(
    struct rawrtc_ice_candidate_mdns_resolver** const resolverp,  // de-referenced
    struct dnsc* const dns_client,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_candidate* const candidate,  // referenced
    char* const hostname,  // copied
    rawrtc_ice_candidate_mdns_address_resolved_handler address_handler,
    void* const arg);
