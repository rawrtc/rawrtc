#include "options.h"
#include "../ice_server/server.h"
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <re.h>

static enum rawrtc_ice_gather_policy const map_enum_ice_gather_policy[] = {
    RAWRTC_ICE_GATHER_POLICY_ALL,
    RAWRTC_ICE_GATHER_POLICY_NOHOST,
    RAWRTC_ICE_GATHER_POLICY_RELAY,
};

static char const * const map_str_ice_gather_policy[] = {
    "all",
    "nohost",
    "relay",
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
