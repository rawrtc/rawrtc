#pragma once

enum rawrtc_code rawrtc_ice_server_create(
    struct rawrtc_ice_server** const serverp,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

enum rawrtc_code rawrtc_ice_server_url_destroy_dns_contexts(
    struct rawrtc_ice_server_url* const url
);

enum rawrtc_code rawrtc_ice_server_destroy_url_dns_contexts(
    struct rawrtc_ice_server* const server
);

enum rawrtc_code rawrtc_ice_server_url_dns_context_create(
    struct rawrtc_ice_server_url_dns_context** const contextp,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_server_url* const url,
    struct rawrtc_ice_gatherer* const gatherer
);

enum rawrtc_code rawrtc_ice_server_dns_queries_pending(
    bool* const pendingp, // de-referenced
    struct rawrtc_ice_server_url** const urlp, // de-referenced
    struct rawrtc_ice_server* const server
);

int rawrtc_ice_server_debug(
    struct re_printf* const pf,
    struct rawrtc_ice_server const* const server
);
