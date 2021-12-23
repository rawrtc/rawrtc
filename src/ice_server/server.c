#include "server.h"
#include "../main/config.h"
#include <rawrtc/config.h>
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>
#include <string.h>  // strlen

#define DEBUG_MODULE "ice-server"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * ICE server URL-related regular expressions.
 */
static char const ice_server_url_regex[] = "[a-z]+:[^?]+[^]*";
static char const ice_server_host_port_regex[] = "[^:]+[:]*[0-9]*";
static char const ice_server_host_port_ipv6_regex[] = "\\[[0-9a-f:]+\\][:]*[0-9]*";
static char const ice_server_transport_regex[] = "\\?transport=[a-z]+";

/*
 * Valid ICE server schemes.
 *
 * Note: Update `ice_server_scheme_type_mapping`,
 * `ice_server_scheme_secure_mapping` and
 * `ice_server_scheme_port_mapping` if changed.
 */
static char const* const ice_server_schemes[] = {
    "stun",
    "stuns",
    "turn",
    "turns",
};
static size_t const ice_server_schemes_length = ARRAY_SIZE(ice_server_schemes);

/*
 * ICE server scheme to server type mapping.
 */
static enum rawrtc_ice_server_type ice_server_scheme_type_mapping[] = {
    RAWRTC_ICE_SERVER_TYPE_STUN,
    RAWRTC_ICE_SERVER_TYPE_STUN,
    RAWRTC_ICE_SERVER_TYPE_TURN,
    RAWRTC_ICE_SERVER_TYPE_TURN,
};

/*
 * ICE server scheme to secure mapping.
 */
static bool ice_server_scheme_secure_mapping[] = {
    false,
    true,
    false,
    true,
};

/*
 * ICE server scheme to default port mapping.
 */
static uint_fast16_t ice_server_scheme_port_mapping[] = {
    3478,
    5349,
    3478,
    5349,
};

/*
 * Valid ICE server transports.
 *
 * Note: Update `ice_server_transport_normal_transport_mapping` and
 * `ice_server_transport_secure_transport_mapping` if changed.
 */
static char const* const ice_server_transports[] = {
    "udp",
    "tcp",
};
static size_t const ice_server_transports_length = ARRAY_SIZE(ice_server_transports);

/*
 * ICE server transport to non-secure transport mapping.
 */
static enum rawrtc_ice_server_transport ice_server_transport_normal_transport_mapping[] = {
    RAWRTC_ICE_SERVER_TRANSPORT_UDP,
    RAWRTC_ICE_SERVER_TRANSPORT_TCP,
};

/*
 * ICE server transport to secure transport mapping.
 */
static enum rawrtc_ice_server_transport ice_server_transport_secure_transport_mapping[] = {
    RAWRTC_ICE_SERVER_TRANSPORT_DTLS,
    RAWRTC_ICE_SERVER_TRANSPORT_TLS,
};

/*
 * Parse ICE server's transport.
 */
static enum rawrtc_code decode_ice_server_transport(
    enum rawrtc_ice_server_transport* const transportp,  // de-referenced, not checked
    struct pl* const query,  // not checked
    bool const secure) {
    enum rawrtc_code error;
    struct pl transport;
    size_t i;

    // Decode transport
    error =
        rawrtc_error_to_code(re_regex(query->p, query->l, ice_server_transport_regex, &transport));
    if (error) {
        return error;
    }

    // Translate transport to ICE server transport
    for (i = 0; i < ice_server_transports_length; ++i) {
        if (pl_strcmp(&transport, ice_server_transports[i]) == 0) {
            if (!secure) {
                *transportp = ice_server_transport_normal_transport_mapping[i];
            } else {
                *transportp = ice_server_transport_secure_transport_mapping[i];
            }
            return RAWRTC_CODE_SUCCESS;
        }
    }

    // Not found
    return RAWRTC_CODE_INVALID_ARGUMENT;
}

/*
 * Parse an ICE scheme to an ICE server type, 'secure' flag and
 * default port.
 */
static enum rawrtc_code decode_ice_server_scheme(
    enum rawrtc_ice_server_type* const typep,  // de-referenced, not checked
    bool* const securep,  // de-referenced, not checked
    uint_fast16_t* const portp,  // de-referenced, not checked
    struct pl* const scheme  // not checked
) {
    size_t i;

    // Translate scheme to ICE server type (and set if secure)
    for (i = 0; i < ice_server_schemes_length; ++i) {
        if (pl_strcmp(scheme, ice_server_schemes[i]) == 0) {
            // Set values
            *typep = ice_server_scheme_type_mapping[i];
            *securep = ice_server_scheme_secure_mapping[i];
            *portp = ice_server_scheme_port_mapping[i];

            // Done
            return RAWRTC_CODE_SUCCESS;
        }
    }

    // Not found
    return RAWRTC_CODE_INVALID_ARGUMENT;
}

/*
 * Parse an ICE server URL according to RFC 7064 and RFC 7065
 * (although the `transport` part is inaccurate for RFC 7064 but it
 * seems useful)
 */
static enum rawrtc_code decode_ice_server_url(
    struct rawrtc_ice_server_url* const url  // not checked
) {
    enum rawrtc_code error;
    struct pl scheme;
    struct pl host_port;
    struct pl query;
    bool secure;
    struct pl port_pl;
    uint_fast16_t port;

    // Decode URL
    error = rawrtc_error_to_code(
        re_regex(url->url, strlen(url->url), ice_server_url_regex, &scheme, &host_port, &query));
    if (error) {
        DEBUG_WARNING("Invalid ICE server URL: %s\n", url->url);
        goto out;
    }

    // TODO: Can scheme or host be NULL?

    // Get server type, secure flag and default port from scheme
    error = decode_ice_server_scheme(&url->type, &secure, &port, &scheme);
    if (error) {
        DEBUG_WARNING("Invalid scheme in ICE server URL (%s): %r\n", url->url, &scheme);
        goto out;
    }

    // Set default address
    sa_set_in(&url->resolved_address, INADDR_ANY, (uint16_t) port);

    // Decode host: Either IPv4 or IPv6 including the port (if any)
    // Try IPv6 first, then normal hostname/IPv4.
    error = rawrtc_error_to_code(re_regex(
        host_port.p, host_port.l, ice_server_host_port_ipv6_regex, &url->host, NULL, &port_pl));
    if (error) {
        error = rawrtc_error_to_code(re_regex(
            host_port.p, host_port.l, ice_server_host_port_regex, &url->host, NULL, &port_pl));
        if (error) {
            DEBUG_WARNING(
                "Invalid host or port in ICE server URL (%s): %r\n", url->url, &host_port);
            goto out;
        }

        // Try decoding IPv4
        sa_set(&url->resolved_address, &url->host, (uint16_t) port);
    } else {
        // Try decoding IPv6
        error = rawrtc_error_to_code(sa_set(&url->resolved_address, &url->host, (uint16_t) port));
        if (error) {
            DEBUG_WARNING(
                "Invalid IPv6 address in ICE server URL (%s): %r\n", url->url, &host_port);
            goto out;
        }
    }

    // Decode port (if any)
    if (pl_isset(&port_pl)) {
        uint_fast32_t port_u32;

        // Get port
        port_u32 = pl_u32(&port_pl);
        if (port_u32 == 0 || port_u32 > UINT16_MAX) {
            DEBUG_WARNING(
                "Invalid port number in ICE server URL (%s): %" PRIu32 "\n", url->url, port_u32);
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Set port
        sa_set_port(&url->resolved_address, (uint16_t) port_u32);
    }

    // Translate transport (if any) & secure flag to ICE server transport
    if (pl_isset(&query)) {
        error = decode_ice_server_transport(&url->transport, &query, secure);
        if (error) {
            DEBUG_WARNING("Invalid transport in ICE server URL (%s): %r\n", url->url, &query);
            goto out;
        }
    } else {
        // Set default transport (depending on secure flag)
        if (secure) {
            url->transport = rawrtc_default_config.ice_server_secure_transport;
        } else {
            url->transport = rawrtc_default_config.ice_server_normal_transport;
        }
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    return error;
}

/*
 * Destructor for URLs of the ICE gatherer.
 */
static void rawrtc_ice_server_url_destroy(void* arg) {
    struct rawrtc_ice_server_url* const url = arg;

    // Remove from list
    list_unlink(&url->le);

    // Un-reference
    mem_deref(url->url);
}

/*
 * Copy a URL for the ICE gatherer.
 */
static enum rawrtc_code rawrtc_ice_server_url_create(
    struct rawrtc_ice_server_url** const urlp,  // de-referenced
    char* const url_s  // copied
) {
    struct rawrtc_ice_server_url* url;
    enum rawrtc_code error;

    // Check arguments
    if (!urlp || !url_s) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    url = mem_zalloc(sizeof(*url), rawrtc_ice_server_url_destroy);
    if (!url) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Copy URL
    error = rawrtc_strdup(&url->url, url_s);
    if (error) {
        goto out;
    }

    // Parse URL
    // Note: `url->host` points inside `url->url`, so we MUST have copied the URL first.
    error = decode_ice_server_url(url);
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(url);
    } else {
        // Set pointer
        *urlp = url;
    }
    return error;
}

/*
 * Destructor for an existing ICE server.
 */
static void rawrtc_ice_server_destroy(void* arg) {
    struct rawrtc_ice_server* const server = arg;

    // Un-reference
    list_flush(&server->urls);
    mem_deref(server->username);
    mem_deref(server->credential);
}

/*
 * Create an ICE server.
 */
enum rawrtc_code rawrtc_ice_server_create(
    struct rawrtc_ice_server** const serverp,  // de-referenced
    char const* const* const urls,  // copied
    size_t const n_urls,
    char const* const username,  // nullable, copied
    char const* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type) {
    struct rawrtc_ice_server* server;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    size_t i;

    // Check arguments
    if (!serverp || !urls) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    server = mem_zalloc(sizeof(*server), rawrtc_ice_server_destroy);
    if (!server) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Copy URLs to list
    list_init(&server->urls);
    for (i = 0; i < n_urls; ++i) {
        struct rawrtc_ice_server_url* url;

        // Ensure URLs aren't null
        if (!urls[i]) {
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Copy URL
        error = rawrtc_ice_server_url_create(&url, urls[i]);
        if (error) {
            goto out;
        }

        // Append URL to list
        list_append(&server->urls, &url->le, url);
    }

    // Set fields
    if (credential_type != RAWRTC_ICE_CREDENTIAL_TYPE_NONE) {
        if (username) {
            error = rawrtc_strdup(&server->username, username);
            if (error) {
                goto out;
            }
        }
        if (credential) {
            error = rawrtc_strdup(&server->credential, credential);
            if (error) {
                goto out;
            }
        }
    }
    server->credential_type = credential_type;  // TODO: Validation needed in case TOKEN is used?

out:
    if (error) {
        mem_deref(server);
    } else {
        // Set pointer
        *serverp = server;
    }
    return error;
}

/*
 * Copy an ICE server.
 */
enum rawrtc_code rawrtc_ice_server_copy(
    struct rawrtc_ice_server** const serverp,  // de-referenced
    struct rawrtc_ice_server* const source_server) {
    size_t n_urls;
    char** urls = NULL;
    struct le* le;
    size_t i;
    enum rawrtc_code error;

    // Check arguments
    if (!serverp || !source_server) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create temporary ICE server URL array
    n_urls = list_count(&source_server->urls);
    if (n_urls > 0) {
        urls = mem_alloc(sizeof(char*) * n_urls, NULL);
        if (!urls) {
            return RAWRTC_CODE_NO_MEMORY;
        }
    }

    // Copy ICE server URL (str) pointers
    for (le = list_head(&source_server->urls), i = 0; le != NULL; le = le->next, ++i) {
        struct rawrtc_ice_server_url* const url = le->data;
        urls[i] = url->url;
    }

    // Copy
    error = rawrtc_ice_server_create(
        serverp, urls, n_urls, source_server->username, source_server->credential,
        source_server->credential_type);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(urls);
    return error;
}
