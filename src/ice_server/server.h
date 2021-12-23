#pragma once
#include <rawrtc/ice_gather_options.h>
#include <rawrtc/ice_server.h>
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE server type.
 * Note: Update `ice_server_schemes` if changed.
 */
enum rawrtc_ice_server_type {
    RAWRTC_ICE_SERVER_TYPE_STUN,
    RAWRTC_ICE_SERVER_TYPE_TURN,
};

struct rawrtc_ice_server {
    struct le le;
    struct list urls;  // deep-copied
    char* username;  // copied
    char* credential;  // copied
    enum rawrtc_ice_credential_type credential_type;
};

/*
 * ICE server URL. (list element)
 */
struct rawrtc_ice_server_url {
    struct le le;
    char* url;  // copied
    struct pl host;  // points inside `url`
    enum rawrtc_ice_server_type type;
    enum rawrtc_ice_server_transport transport;
    struct sa resolved_address;
};

enum rawrtc_code rawrtc_ice_server_create(
    struct rawrtc_ice_server** const serverp,  // de-referenced
    char const* const* const urls,  // copied
    size_t const n_urls,
    char const* const username,  // nullable, copied
    char const* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type);

enum rawrtc_code rawrtc_ice_server_copy(
    struct rawrtc_ice_server** const serverp,  // de-referenced
    struct rawrtc_ice_server* const source_server);

int rawrtc_ice_server_debug(
    struct re_printf* const pf, struct rawrtc_ice_server const* const server);
