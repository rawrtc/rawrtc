#pragma once
#include <rawrtc.h>
#include "ice_server.h"

enum {
    RAWRTC_ICE_GATHERER_DNS_SERVERS = 10
};

struct rawrtc_ice_gatherer {
    enum rawrtc_ice_gatherer_state state;
    struct rawrtc_ice_gather_options* options; // referenced
    rawrtc_ice_gatherer_state_change_handler* state_change_handler; // nullable
    rawrtc_ice_gatherer_error_handler* error_handler; // nullable
    rawrtc_ice_gatherer_local_candidate_handler* local_candidate_handler; // nullable
    void* arg; // nullable
    struct list buffered_messages; // TODO: Can this be added to the candidates list?
    struct list local_candidates; // TODO: Hash list instead?
    char ice_username_fragment[ICE_USERNAME_FRAGMENT_LENGTH + 1];
    char ice_password[ICE_PASSWORD_LENGTH + 1];
    struct trice* ice;
    struct trice_conf ice_config;
    struct dnsc* dns_client;
};

enum rawrtc_code rawrtc_ice_server_url_dns_context_create(
    struct rawrtc_ice_server_url_dns_context** const contextp,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_server_url* const url,
    struct rawrtc_ice_gatherer* const gatherer // referenced
);
