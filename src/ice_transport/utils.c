#include "transport.h"
#include <rawrtc/ice_transport.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <rew.h>

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * rawrtc_ice_transport_state_to_name(
        enum rawrtc_ice_transport_state const state
) {
    switch (state) {
        case RAWRTC_ICE_TRANSPORT_STATE_NEW:
            return "new";
        case RAWRTC_ICE_TRANSPORT_STATE_CHECKING:
            return "checking";
        case RAWRTC_ICE_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case RAWRTC_ICE_TRANSPORT_STATE_COMPLETED:
            return "completed";
        case RAWRTC_ICE_TRANSPORT_STATE_DISCONNECTED:
            return "disconnected";
        case RAWRTC_ICE_TRANSPORT_STATE_FAILED:
            return "failed";
        case RAWRTC_ICE_TRANSPORT_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

static enum rawrtc_ice_role const map_enum_ice_role[] = {
    RAWRTC_ICE_ROLE_CONTROLLING,
    RAWRTC_ICE_ROLE_CONTROLLED,
};

static char const * const map_str_ice_role[] = {
    "controlling",
    "controlled",
};

static size_t const map_ice_role_length = ARRAY_SIZE(map_enum_ice_role);

/*
 * Translate an ICE role to str.
 */
char const * rawrtc_ice_role_to_str(
        enum rawrtc_ice_role const role
) {
    size_t i;

    for (i = 0; i < map_ice_role_length; ++i) {
        if (map_enum_ice_role[i] == role) {
            return map_str_ice_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_role_length; ++i) {
        if (str_casecmp(map_str_ice_role[i], str) == 0) {
            *rolep = map_enum_ice_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE role to the corresponding re type.
 */
enum ice_role rawrtc_ice_role_to_re_ice_role(
        enum rawrtc_ice_role const role
) {
    // No conversion needed
    return (enum ice_role) role;
}

/*
 * Translate a re ICE role to the corresponding rawrtc role.
 */
enum rawrtc_code rawrtc_re_ice_role_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        enum ice_role const re_role
) {
    // Check arguments
    if (!rolep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Translate role
    switch (re_role) {
        case ICE_ROLE_CONTROLLING:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLING;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_CONTROLLED:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLED;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_UNKNOWN:
            *rolep = RAWRTC_ICE_ROLE_UNKNOWN;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}
