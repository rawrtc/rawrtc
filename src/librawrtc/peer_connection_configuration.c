#include <rawrtc.h>
#include "ice_server.h"
#include "peer_connection_configuration.h"

#define DEBUG_MODULE "peer-connection-configuration"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Destructor for an existing peer connection configuration.
 */
static void rawrtc_peer_connection_configuration_destroy(
        void* arg
) {
    struct rawrtc_peer_connection_configuration* const configuration = arg;

    // Un-reference
    list_flush(&configuration->certificates);
    list_flush(&configuration->ice_servers);
}

/*
 * Create a new peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_create(
        struct rawrtc_peer_connection_configuration** const configurationp, // de-referenced
        enum rawrtc_ice_gather_policy const gather_policy
) {
    struct rawrtc_peer_connection_configuration* configuration;

    // Check arguments
    if (!configurationp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    configuration = mem_zalloc(
            sizeof(*configuration), rawrtc_peer_connection_configuration_destroy);
    if (!configuration) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    configuration->gather_policy = gather_policy;
    list_init(&configuration->ice_servers);
    list_init(&configuration->certificates);
    configuration->sctp_sdp_06 = true;

    // Set pointer and return
    *configurationp = configuration;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server instance to the peer connection configuration.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_add_server_internal(
        struct rawrtc_peer_connection_configuration* const configuration,
        struct rawrtc_ice_server* const server
) {
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
enum rawrtc_code rawrtc_peer_connection_configuration_add_server(
        struct rawrtc_peer_connection_configuration* const configuration,
        char* const * const urls, // copied
        size_t const n_urls,
        char* const username, // nullable, copied
        char* const credential, // nullable, copied
        enum rawrtc_ice_credential_type const credential_type
) {
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
    return rawrtc_peer_connection_configuration_add_server_internal(configuration, server);
}

/*
 * Set whether to use legacy SDP for data channel parameter encoding.
 * Note: Currently, legacy SDP for data channels is on by default.
 */
enum rawrtc_code rawrtc_peer_connection_configuration_set_sctp_sdp_06(
        struct rawrtc_peer_connection_configuration* configuration,
        bool const on
) {
    // Check parameters
    if (!configuration) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set
    configuration->sctp_sdp_06 = on;
    return RAWRTC_CODE_SUCCESS;
}
