#pragma once
#include <anyrtc.h>

/*
 * ICE gather options.
 */
struct anyrtc_ice_gather_options {
    enum anyrtc_ice_gather_policy gather_policy;
    struct list* ice_servers; // referenced
};

/*
 * ICE server.
 */
struct anyrtc_ice_server {
    struct list* const urls; // deep-copied
    char* username; // copied
    char* credential; // copied
    enum anyrtc_ice_credential_type credential_type;
};

/*
 * ICE gatherer.
 */
struct anyrtc_ice_gatherer {
    struct anyrtc_ice_gather_options* options; // referenced
    enum anyrtc_ice_gatherer_state state;
};
