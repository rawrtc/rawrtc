#include "server.h"
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <re.h>

/*
 * Get the corresponding name for an ICE server type.
 */
static char const* ice_server_type_to_name(enum rawrtc_ice_server_type const type) {
    switch (type) {
        case RAWRTC_ICE_SERVER_TYPE_STUN:
            return "stun";
        case RAWRTC_ICE_SERVER_TYPE_TURN:
            return "turn";
        default:
            return "???";
    }
}

/*
 * Get the corresponding name for an ICE server transport.
 */
static char const* ice_server_transport_to_name(enum rawrtc_ice_server_transport const transport) {
    switch (transport) {
        case RAWRTC_ICE_SERVER_TRANSPORT_UDP:
            return "udp";
        case RAWRTC_ICE_SERVER_TRANSPORT_TCP:
            return "tcp";
        case RAWRTC_ICE_SERVER_TRANSPORT_DTLS:
            return "dtls";
        case RAWRTC_ICE_SERVER_TRANSPORT_TLS:
            return "tls";
        default:
            return "???";
    }
}

/*
 * Get the corresponding name for an ICE credential type.
 */
static char const* ice_credential_type_to_name(enum rawrtc_ice_credential_type const type) {
    switch (type) {
        case RAWRTC_ICE_CREDENTIAL_TYPE_NONE:
            return "n/a";
        case RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD:
            return "password";
        case RAWRTC_ICE_CREDENTIAL_TYPE_TOKEN:
            return "token";
        default:
            return "???";
    }
}

/*
 * Print debug information for an ICE server.
 */
int rawrtc_ice_server_debug(
    struct re_printf* const pf, struct rawrtc_ice_server const* const server) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!server) {
        return 0;
    }

    err |= re_hprintf(pf, "  ICE Server <%p>:\n", server);

    // Credential type
    err |= re_hprintf(
        pf, "    credential_type=%s\n", ice_credential_type_to_name(server->credential_type));
    if (server->credential_type != RAWRTC_ICE_CREDENTIAL_TYPE_NONE) {
        // Username
        err |= re_hprintf(pf, "    username=");
        if (server->username) {
            err |= re_hprintf(pf, "\"%s\"\n", server->username);
        } else {
            err |= re_hprintf(pf, "n/a\n");
        }

        // Credential
        err |= re_hprintf(pf, "    credential=");
        if (server->credential) {
            err |= re_hprintf(pf, "\"%s\"\n", server->credential);
        } else {
            err |= re_hprintf(pf, "n/a\n");
        }
    }

    // URLs
    for (le = list_head(&server->urls); le != NULL; le = le->next) {
        struct rawrtc_ice_server_url* const url = le->data;

        // URL, STUN/TURN, transport, currently gathering?
        err |= re_hprintf(
            pf, "    URL=\"%s\" type=%s transport=%s resolved=%s\n", url->url,
            ice_server_type_to_name(url->type), ice_server_transport_to_name(url->transport),
            sa_is_any(&url->resolved_address) ? "no" : "yes");
    }

    // Done
    return err;
}
