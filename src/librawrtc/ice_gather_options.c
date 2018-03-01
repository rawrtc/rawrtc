#include <rawrtc.h>
#include "ice_server.h"
#include "ice_gather_options.h"

#define DEBUG_MODULE "ice-gather-options"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

/*
 * Destructor for an existing ICE gather options instance.
 */
static void rawrtc_ice_gather_options_destroy(
        void* arg
) {
    struct rawrtc_ice_gather_options* const options = arg;

    // Un-reference
    list_flush(&options->ice_servers);
}

/*
 * Create a new ICE gather options instance.
 * `*optionsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gather_options_create(
        struct rawrtc_ice_gather_options** const optionsp, // de-referenced
        enum rawrtc_ice_gather_policy const gather_policy
) {
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
        struct rawrtc_ice_gather_options* const options,
        struct rawrtc_ice_server* const server
) {
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
        char* const * const urls, // copied
        size_t const n_urls,
        char* const username, // nullable, copied
        char* const credential, // nullable, copied
        enum rawrtc_ice_credential_type const credential_type
) {
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

static enum rawrtc_ice_gather_policy const map_enum_ice_gather_policy[] = {
    RAWRTC_ICE_GATHER_POLICY_ALL,
    RAWRTC_ICE_GATHER_POLICY_NOHOST,
    RAWRTC_ICE_GATHER_POLICY_RELAY
};

static char const * const map_str_ice_gather_policy[] = {
    "all",
    "nohost",
    "relay"
};

static size_t const map_ice_gather_policy_length = ARRAY_SIZE(map_enum_ice_gather_policy);

/*
 * Translate an ICE gather policy to str.
 */
char const * rawrtc_ice_gather_policy_to_str(
        enum rawrtc_ice_gather_policy const policy
) {
    size_t i;

    for (i = 0; i < map_ice_gather_policy_length; ++i) {
        if (map_enum_ice_gather_policy[i] == policy) {
            return map_str_ice_gather_policy[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE gather policy (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_gather_policy(
        enum rawrtc_ice_gather_policy* const policyp, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!policyp || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_gather_policy_length; ++i) {
        if (str_casecmp(map_str_ice_gather_policy[i], str) == 0) {
            *policyp = map_enum_ice_gather_policy[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Destroy all ICE server URL DNS contexts.
 */
enum rawrtc_code rawrtc_ice_gather_options_destroy_url_dns_contexts(
        struct rawrtc_ice_gather_options* const options
) {
    // Check arguments
    if (!options) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Destroy all URL DNS contexts
    struct le* le;
    for (le = list_head(&options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;

        // Destroy DNS contexts
        enum rawrtc_code const error = rawrtc_ice_server_destroy_dns_contexts(server);
        if (error) {
            DEBUG_WARNING("Unable to destroy DNS contexts of server, reason: %s\n",
                          rawrtc_code_to_str(error));
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Print debug information for the ICE gather options.
 */
int rawrtc_ice_gather_options_debug(
        struct re_printf* const pf,
        struct rawrtc_ice_gather_options const* const options
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!options) {
        return 0;
    }

    err |= re_hprintf(pf, "----- ICE Gather Options <%p> -----\n", options);

    // Gather policy
    err |= re_hprintf(pf, "  gather_policy=%s\n",
                      rawrtc_ice_gather_policy_to_str(options->gather_policy));

    // ICE servers
    for (le = list_head(&options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;
        err |= re_hprintf(pf, "%H", rawrtc_ice_server_debug, server);
    }

    // Done
    return err;
}
