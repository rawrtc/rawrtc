#pragma once

enum rawrtc_code rawrtc_ice_server_create(
    struct rawrtc_ice_server** const serverp, // de-referenced
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
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
