#pragma once
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <re.h>

struct rawrtc_ice_gather_options {
    enum rawrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
};

enum rawrtc_code rawrtc_ice_gather_options_add_server_internal(
    struct rawrtc_ice_gather_options* const configuration, struct rawrtc_ice_server* const server);

int rawrtc_ice_gather_options_debug(
    struct re_printf* const pf, struct rawrtc_ice_gather_options const* const options);
