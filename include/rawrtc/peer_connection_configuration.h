#pragma once
#include "ice_gather_options.h"
#include <rawrtcc/code.h>
#include <rawrtcdc/sctp_transport.h>
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
    struct rawrtc_peer_connection_configuration** const configurationp,  // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy);

/*
 * Add an ICE server to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server(
    struct rawrtc_peer_connection_configuration* const configuration,
    char* const* const urls,  // copied
    size_t const n_urls,
    char* const username,  // nullable, copied
    char* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type);

/*
 * Get ICE servers from the peer connection configuration.
 * `*serversp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_ice_servers(
    struct rawrtc_ice_servers** const serversp,  // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration);

/*
 * Add a certificate to the peer connection configuration to be used
 * instead of an ephemerally generated one.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_certificate(
    struct rawrtc_peer_connection_configuration* configuration,
    struct rawrtc_certificate* const certificate  // copied
);

/*
 * Get certificates from the peer connection configuration.
 * `*certificatesp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_certificates(
    struct rawrtc_certificates** const certificatesp,  // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration);

/*
 * Set whether to use legacy SDP for data channel parameter encoding.
 * Note: Legacy SDP for data channels is on by default due to parsing problems in Chrome.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_sdp_05(
    struct rawrtc_peer_connection_configuration* configuration, bool on);

/*
 * Set the SCTP transport's send and receive buffer length in bytes.
 * If both values are zero, the default buffer length will be used. Otherwise,
 * zero is invalid.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_buffer_length(
    struct rawrtc_peer_connection_configuration* configuration,
    uint32_t send_buffer_length,
    uint32_t receive_buffer_length);

/*
 * Set the SCTP transport's congestion control algorithm.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_congestion_ctrl_algorithm(
    struct rawrtc_peer_connection_configuration* configuration,
    enum rawrtc_sctp_transport_congestion_ctrl algorithm);

/*
 * Set the SCTP transport's maximum transmission unit (MTU).
 * A value of zero indicates that the default MTU should be used.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_mtu(
    struct rawrtc_peer_connection_configuration* configuration, uint32_t mtu);

/*
 * Enable or disable MTU discovery on the SCTP transport.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_mtu_discovery(
    struct rawrtc_peer_connection_configuration* configuration, bool on);
