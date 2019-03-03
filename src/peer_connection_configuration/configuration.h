#pragma once
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <re.h>

struct rawrtc_peer_connection_configuration {
    enum rawrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
    struct list certificates;
    bool sctp_sdp_05;
};

enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server_internal(
    struct rawrtc_peer_connection_configuration* const configuration,
    struct rawrtc_ice_server* const server
);
