#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "ice-gatherer-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Print the ICE gatherer's state. Stop once complete.
 */
void gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg // will be casted to `struct client*`
) {
    default_ice_gatherer_state_change_handler(state, arg);
    if (state == RAWRTC_ICE_GATHERER_STATE_COMPLETE) {
        re_cancel();
    }
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* gatherer;
    char* const turn_zwuenf_org_ipv4_urls[] = {"stun:217.160.182.235"};
    char* const turn_threema_ch_ipv6_urls[] = {"stun:[2a02:418:3009:303::197]:443"};
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
    char* const turn_threema_ch_urls[] = {"turn:turn.threema.ch:443"};
    struct client client = {0};

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Initialise
    EOE(rawrtc_init(true));

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL));

    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_ipv4_urls, ARRAY_SIZE(turn_zwuenf_org_ipv4_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_threema_ch_ipv6_urls, ARRAY_SIZE(turn_threema_ch_ipv6_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_threema_ch_urls, ARRAY_SIZE(turn_threema_ch_urls),
            "threema-angular", "Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
            RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD));

    // Setup client
    client.name = "A";

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &gatherer, gather_options,
            gatherer_state_change_handler, default_ice_gatherer_error_handler,
            default_ice_gatherer_local_candidate_handler, &client));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(gatherer, NULL));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Close gatherer
    EOE(rawrtc_ice_gatherer_close(gatherer));

    // Un-reference & close
    mem_deref(gatherer);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
