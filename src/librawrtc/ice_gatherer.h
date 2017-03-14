#pragma once

enum {
    RAWRTC_ICE_GATHERER_DNS_SERVERS = 10
};

enum rawrtc_code rawrtc_ice_server_url_dns_context_create(
    struct rawrtc_ice_server_url_dns_context** const contextp,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_server_url* const url,
    struct rawrtc_ice_gatherer* const gatherer
);
