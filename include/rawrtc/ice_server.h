#pragma once
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE server transport protocol.
 */
enum rawrtc_ice_server_transport {
    RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    RAWRTC_ICE_SERVER_TRANSPORT_TCP,
    RAWRTC_ICE_SERVER_TRANSPORT_DTLS,
    RAWRTC_ICE_SERVER_TRANSPORT_TLS,
};

/*
 * ICE server.
 */
struct rawrtc_ice_server;

/*
 * ICE servers.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_ice_servers {
    size_t n_servers;
    struct rawrtc_ice_server* servers[];
};
