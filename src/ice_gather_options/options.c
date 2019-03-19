#include "options.h"
#include "../ice_server/server.h"
#include <rawrtc/ice_gather_options.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Destructor for an existing ICE gather options instance.
 */
static void rawrtc_ice_gather_options_destroy(void* arg) {
    struct rawrtc_ice_gather_options* const options = arg;

    // Un-reference
    list_flush(&options->ice_servers);
}

/*
 * Create a new ICE gather options instance.
 * `*optionsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gather_options_create(
    struct rawrtc_ice_gather_options** const optionsp,  // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy) {
    struct rawrtc_ice_gather_options* options;

    // Check arguments
    if (!optionsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    options = mem_zalloc(sizeof(*options), rawrtc_ice_gather_options_destroy);
    if (!options) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    options->gather_policy = gather_policy;
    list_init(&options->ice_servers);

    // Set pointer and return
    *optionsp = options;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server instance to the gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_add_server_internal(
    struct rawrtc_ice_gather_options* const options, struct rawrtc_ice_server* const server) {
    // Check arguments
    if (!options || !server) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Add to options
    list_append(&options->ice_servers, &server->le, server);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server to the gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_add_server(
    struct rawrtc_ice_gather_options* const options,
    char* const* const urls,  // copied
    size_t const n_urls,
    char* const username,  // nullable, copied
    char* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type) {
    struct rawrtc_ice_server* server;
    enum rawrtc_code error;

    // Check arguments
    if (!options) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure there are less than 2^8 servers
    // TODO: This check should be in some common location
    if (list_count(&options->ice_servers) == UINT8_MAX) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Create ICE server
    error = rawrtc_ice_server_create(&server, urls, n_urls, username, credential, credential_type);
    if (error) {
        return error;
    }

    // Add to options
    return rawrtc_ice_gather_options_add_server_internal(options, server);
}
