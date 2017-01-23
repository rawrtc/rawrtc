#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "ice-gatherer-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* gatherer;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct client client = {0};

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

    // Setup client
    client.name = "A";

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &gatherer, gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            default_ice_gatherer_local_candidate_handler, &client));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(gatherer, NULL));

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOR(re_main(default_signal_handler));

    // Close gatherer
    EOE(rawrtc_ice_gatherer_close(gatherer));

    // Dereference & close
    mem_deref(gatherer);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
