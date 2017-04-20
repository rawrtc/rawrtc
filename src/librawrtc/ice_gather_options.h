#pragma once

enum rawrtc_code rawrtc_ice_gather_options_add_server_internal(
    struct rawrtc_ice_gather_options* const configuration,
    struct rawrtc_ice_server* const server
);

enum rawrtc_code rawrtc_ice_gather_options_destroy_url_dns_contexts(
    struct rawrtc_ice_gather_options* const options // not checked
);
