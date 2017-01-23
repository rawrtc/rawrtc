#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "ice-transport-loopback-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// Note: Shadows struct client
struct ice_transport_client {
    char* name;
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_parameters* ice_parameters;
    enum rawrtc_ice_role role;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct ice_transport_client* other_client;
};

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct ice_transport_client* const client = arg;
    
    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);
    
    // Add to other client as remote candidate
    EOE(rawrtc_ice_transport_add_remote_candidate(client->other_client->ice_transport, candidate));
}

static void client_init(
        struct ice_transport_client* const local
) {
    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &local->gatherer, local->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, local));
}

static void client_start(
        struct ice_transport_client* const local,
        struct ice_transport_client* const remote
) {
    // Get & set ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local->ice_parameters, remote->gatherer));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(local->gatherer, NULL));

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            local->ice_transport, local->gatherer, local->ice_parameters, local->role));
}

static void client_stop(
        struct ice_transport_client* const client
) {
    // Stop transport & close gatherer
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct ice_transport_client a = {0};
    struct ice_transport_client b = {0};

    // Initialise
    EOE(rawrtc_init());

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_ALL));

    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls,
            sizeof(stun_google_com_urls) / sizeof(stun_google_com_urls[0]),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org_urls) / sizeof(turn_zwuenf_org_urls[0]),
            "bruno", "onurb", RAWRTC_ICE_CREDENTIAL_PASSWORD));

    // Setup client A
    a.name = "A";
    a.gather_options = gather_options;
    a.role = RAWRTC_ICE_ROLE_CONTROLLING;
    a.other_client = &b;

    // Setup client B
    b.name = "B";
    b.gather_options = gather_options;
    b.role = RAWRTC_ICE_ROLE_CONTROLLED;
    b.other_client = &a;

    // Initialise clients
    client_init(&a);
    client_init(&b);

    // Start clients
    client_start(&a, &b);
    client_start(&b, &a);

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
