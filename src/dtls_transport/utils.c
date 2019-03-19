#include <rawrtc/dtls_transport.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Get the corresponding name for an ICE transport state.
 */
char const* rawrtc_dtls_transport_state_to_name(enum rawrtc_dtls_transport_state const state) {
    switch (state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_NEW:
            return "new";
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            return "connecting";
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case RAWRTC_DTLS_TRANSPORT_STATE_CLOSED:
            return "closed";
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            return "failed";
        default:
            return "???";
    }
}

static enum rawrtc_dtls_role const map_enum_dtls_role[] = {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER,
};

static char const* const map_str_dtls_role[] = {
    "auto",
    "client",
    "server",
};

static size_t const map_dtls_role_length = ARRAY_SIZE(map_enum_dtls_role);

/*
 * Translate a DTLS role to str.
 */
char const* rawrtc_dtls_role_to_str(enum rawrtc_dtls_role const role) {
    size_t i;

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (map_enum_dtls_role[i] == role) {
            return map_str_dtls_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to a DTLS role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_dtls_role(
    enum rawrtc_dtls_role* const rolep,  // de-referenced
    char const* const str) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (str_casecmp(map_str_dtls_role[i], str) == 0) {
            *rolep = map_enum_dtls_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}
