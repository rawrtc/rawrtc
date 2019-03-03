#pragma once
#include "ice_gather_options.h"
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_certificate;
struct rawrtc_certificates;
struct rawrtc_ice_servers;

/*
 * Peer connection configuration.
 */
struct rawrtc_peer_connection_configuration;

/*
 * Create a new peer connection configuration.
 * `*configurationp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_create(
    struct rawrtc_peer_connection_configuration** const configurationp, // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy
);

/*
 * Add an ICE server to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server(
    struct rawrtc_peer_connection_configuration* const configuration,
    char* const * const urls, // copied
    size_t const n_urls,
    char* const username, // nullable, copied
    char* const credential, // nullable, copied
    enum rawrtc_ice_credential_type const credential_type
);

/*
 * Get ICE servers from the peer connection configuration.
 * `*serversp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_ice_servers(
    struct rawrtc_ice_servers** const serversp, // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration
);

/*
 * Add a certificate to the peer connection configuration to be used
 * instead of an ephemerally generated one.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_certificate(
    struct rawrtc_peer_connection_configuration* configuration,
    struct rawrtc_certificate* const certificate // copied
);

/*
 * Get certificates from the peer connection configuration.
 * `*certificatesp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_certificates(
    struct rawrtc_certificates** const certificatesp, // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration
);

/*
 * Set whether to use legacy SDP for data channel parameter encoding.
 * Note: Legacy SDP for data channels is on by default due to parsing problems in Chrome.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_sdp_05(
    struct rawrtc_peer_connection_configuration* configuration,
    bool const on
);
