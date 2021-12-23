#pragma once
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/sctp_transport.h>
#include <re.h>

struct rawrtc_peer_connection_configuration {
    enum rawrtc_ice_gather_policy gather_policy;
    struct list ice_servers;
    struct list certificates;
    bool sctp_sdp_05;
    struct {
        uint32_t send_buffer_length;
        uint32_t receive_buffer_length;
        enum rawrtc_sctp_transport_congestion_ctrl congestion_ctrl_algorithm;
        uint32_t mtu;
        bool mtu_discovery;
    } sctp;
    struct {
        uint16_t min;
        uint16_t max;
    } ice_udp_port_range;
};

enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server_internal(
    struct rawrtc_peer_connection_configuration* const configuration,
    struct rawrtc_ice_server* const server);
