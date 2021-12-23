#include "helper/handler.h"
#include "helper/utils.h"
#include <rawrtc.h>
#include <rawrtcc.h>
#include <rawrtcdc.h>
#include <re.h>

#define DEBUG_MODULE "ice-gatherer-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Print the ICE gatherer's state. Stop once complete.
 */
static void gatherer_state_change_handler(
    enum rawrtc_ice_gatherer_state const state,  // read-only
    void* const arg  // will be casted to `struct client*`
) {
    default_ice_gatherer_state_change_handler(state, arg);
    if (state == RAWRTC_ICE_GATHERER_STATE_COMPLETE) {
        re_cancel();
    }
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* gatherer;
    char* const turn_zwuenf_org_urls[] = {"stun:turn.zwuenf.org"};
    char* const stun_google_com_ip_urls[] = {
        "stun:[2a00:1450:400c:c08::7f]:19302", "stun:74.125.140.127:19302"};
    char* const unreachable_urls[] = {
        "stun:example.com:12345", "stun:lets.assume.no-one-will-ever-register-this"};
    struct client client = {0};
    (void) argv;

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Initialise
    EOE(rawrtc_init(true));

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL));

    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
        gather_options, turn_zwuenf_org_urls, ARRAY_SIZE(turn_zwuenf_org_urls), NULL, NULL,
        RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
        gather_options, stun_google_com_ip_urls, ARRAY_SIZE(stun_google_com_ip_urls), NULL, NULL,
        RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
        gather_options, unreachable_urls, ARRAY_SIZE(unreachable_urls), NULL, NULL,
        RAWRTC_ICE_CREDENTIAL_TYPE_NONE));

    // Setup client
    client.name = "A";

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
        &gatherer, gather_options, gatherer_state_change_handler,
        default_ice_gatherer_error_handler, default_ice_gatherer_local_candidate_handler, &client));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(gatherer, NULL));

    // Start main loop
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
