#include <rawrtc.h>
#include "config.h"

/*
 * Default rawrtc configuration.
 */
struct rawrtc_config rawrtc_default_config = {
    .pacing_interval = 20,
    .ipv4_enable = true,
    .ipv6_enable = true,
    .udp_enable = true,
    .tcp_enable = false, // TODO: true by default
    .sign_algorithm = RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256,
    .ice_server_normal_transport = RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    .ice_server_secure_transport = RAWRTC_ICE_SERVER_TRANSPORT_TLS,
    .stun_keepalive_interval = 25,
    .stun_config = {
        STUN_DEFAULT_RTO,
        STUN_DEFAULT_RC,
        STUN_DEFAULT_RM,
        STUN_DEFAULT_TI,
        0x00
    }
};
