#include "configuration.h"
#include "../certificate/certificate.h"
#include "../ice_server/server.h"
#include "../utils/utils.h"
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/peer_connection_configuration.h>
#include <rawrtc/utils.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/sctp_transport.h>
#include <re.h>
#include <limits.h>  // INT_MAX

/*
 * Destructor for an existing peer connection configuration.
 */
static void rawrtc_peer_connection_configuration_destroy(void* arg) {
    struct rawrtc_peer_connection_configuration* const configuration = arg;

    // Un-reference
    list_flush(&configuration->certificates);
    list_flush(&configuration->ice_servers);
}

/*
 * Create a new peer connection configuration.
 * `*configurationp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_create(
    struct rawrtc_peer_connection_configuration** const configurationp,  // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy) {
    struct rawrtc_peer_connection_configuration* configuration;

    // Check arguments
    if (!configurationp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    configuration =
        mem_zalloc(sizeof(*configuration), rawrtc_peer_connection_configuration_destroy);
    if (!configuration) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    configuration->gather_policy = gather_policy;
    list_init(&configuration->ice_servers);
    list_init(&configuration->certificates);
    configuration->sctp_sdp_05 = true;
    configuration->sctp.send_buffer_length = 0;
    configuration->sctp.receive_buffer_length = 0;
    configuration->sctp.congestion_ctrl_algorithm = RAWRTC_SCTP_TRANSPORT_CONGESTION_CTRL_RFC2581;
    configuration->sctp.mtu = 0;
    configuration->sctp.mtu_discovery = false;

    // Set pointer and return
    *configurationp = configuration;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server instance to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server_internal(
    struct rawrtc_peer_connection_configuration* const configuration,
    struct rawrtc_ice_server* const server) {
    // Check arguments
    if (!configuration || !server) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Add to configuration
    list_append(&configuration->ice_servers, &server->le, server);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_ice_server(
    struct rawrtc_peer_connection_configuration* const configuration,
    char* const* const urls,  // copied
    size_t const n_urls,
    char* const username,  // nullable, copied
    char* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type) {
    struct rawrtc_ice_server* server;
    enum rawrtc_code error;

    // Check arguments
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure there are less than 2^8 servers
    // TODO: This check should be in some common location
    if (list_count(&configuration->ice_servers) == UINT8_MAX) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Create ICE server
    error = rawrtc_ice_server_create(&server, urls, n_urls, username, credential, credential_type);
    if (error) {
        return error;
    }

    // Add to configuration
    return rawrtc_peer_connection_configuration_add_ice_server_internal(configuration, server);
}

/*
 * Get ICE servers from the peer connection configuration.
 * `*serversp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_ice_servers(
    struct rawrtc_ice_servers** const serversp,  // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration) {
    // Check arguments
    if (!serversp || !configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Hand out list as array
    // Note: ICE servers handed out cannot be added to other lists
    //       without copying since the items are only referenced.
    return rawrtc_list_to_array(
        (struct rawrtc_array_container**) serversp, &configuration->ice_servers, true);
}

/*
 * Add a certificate to the peer connection configuration to be used
 * instead of an ephemerally generated one.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_certificate(
    struct rawrtc_peer_connection_configuration* configuration,
    struct rawrtc_certificate* const certificate  // copied
) {
    enum rawrtc_code error;
    struct rawrtc_certificate* certificate_copy;

    // Check arguments
    if (!configuration || !certificate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy certificate
    // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
    error = rawrtc_certificate_copy(&certificate_copy, certificate);
    if (error) {
        return error;
    }

    // Append to list
    list_append(&configuration->certificates, &certificate_copy->le, certificate_copy);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get certificates from the peer connection configuration.
 * `*certificatesp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_get_certificates(
    struct rawrtc_certificates** const certificatesp,  // de-referenced
    struct rawrtc_peer_connection_configuration* const configuration) {
    // Check arguments
    if (!certificatesp || !configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Hand out list as array
    // Note: Certificates handed out cannot be added to other lists
    //       without copying since the items are only referenced.
    return rawrtc_list_to_array(
        (struct rawrtc_array_container**) certificatesp, &configuration->certificates, true);
}

/*
 * Set whether to use legacy SDP for data channel parameter encoding.
 * Note: Legacy SDP for data channels is on by default due to parsing problems in Chrome.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_sdp_05(
    struct rawrtc_peer_connection_configuration* configuration, bool const on) {
    // Check parameters
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set
    configuration->sctp_sdp_05 = on;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set the SCTP transport's send and receive buffer length in bytes.
 * If both values are zero, the default buffer length will be used. Otherwise,
 * zero is invalid.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_buffer_length(
    struct rawrtc_peer_connection_configuration* configuration,
    uint32_t const send_buffer_length,
    uint32_t const receive_buffer_length) {
    // Check arguments
    if (!configuration || send_buffer_length > INT_MAX || receive_buffer_length > INT_MAX ||
        (send_buffer_length == 0 && receive_buffer_length != 0) ||
        (send_buffer_length != 0 && receive_buffer_length == 0)) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set length for send/receive buffer
    configuration->sctp.send_buffer_length = send_buffer_length;
    configuration->sctp.receive_buffer_length = receive_buffer_length;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set the SCTP transport's congestion control algorithm.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_congestion_ctrl_algorithm(
    struct rawrtc_peer_connection_configuration* configuration,
    enum rawrtc_sctp_transport_congestion_ctrl const algorithm) {
    // Check arguments
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set
    configuration->sctp.congestion_ctrl_algorithm = algorithm;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set the SCTP transport's maximum transmission unit (MTU).
 * A value of zero indicates that the default MTU should be used.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_mtu(
    struct rawrtc_peer_connection_configuration* configuration, uint32_t const mtu) {
    // Check arguments
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set
    configuration->sctp.mtu = mtu;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Enable or disable MTU discovery on the SCTP transport.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_mtu_discovery(
    struct rawrtc_peer_connection_configuration* configuration, bool const on) {
    // Check arguments
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set
    configuration->sctp.mtu_discovery = on;
    return RAWRTC_CODE_SUCCESS;
}
