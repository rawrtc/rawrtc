#include "config.h"
#include <rawrtc/certificate.h>
#include <rawrtc/ice_server.h>
#include <re.h>

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
        .rto = STUN_DEFAULT_RTO,
        .rc = STUN_DEFAULT_RC,
        .rm = STUN_DEFAULT_RM,
        .ti = STUN_DEFAULT_TI,
        .tos = 0x00,
    },
};
