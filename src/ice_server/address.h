#pragma once
#include "server.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE server URL's resolved address.
 */
struct rawrtc_ice_server_url_address {
    struct le le;
    struct rawrtc_ice_server_url* url;  // referenced
    struct sa address;
};

enum rawrtc_code rawrtc_ice_server_url_address_create(
    struct rawrtc_ice_server_url_address** const addressp,  // de-referenced
    struct rawrtc_ice_server_url* const url,  // referenced
    struct sa* const address  // copied
);
