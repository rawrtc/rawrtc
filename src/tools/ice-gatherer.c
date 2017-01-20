#include <stdio.h>
#include <rawrtc.h>
#include "../librawrtc/utils.h" /* TODO: Replace with <rawrtc_internal/utils.h> */

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "ice-gatherer-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

static void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg
) {
    (void) arg;
    DEBUG_PRINTF("ICE gatherer state: %s\n", rawrtc_ice_gatherer_state_to_name(state));
}

static void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg
) {
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_PRINTF("ICE gatherer error, URL: %s, reason: %s\n", url, error_text);
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    (void) candidate; (void) arg;
    DEBUG_PRINTF("ICE gatherer local candidate, URL: %s\n", url);
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_gatherer* gatherer;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};

    // Initialise
    EOE(rawrtc_init());

    // Debug
    // TODO: This should be replaced by our own debugging system
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

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &gatherer, gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, NULL));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(gatherer, NULL));

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(rawrtc_error_to_code(re_main(signal_handler)));

    // Close gatherer
    EOE(rawrtc_ice_gatherer_close(gatherer));

    // Dereference & close
    mem_deref(gatherer);
    mem_deref(gather_options);

    // Bye
    rawrtc_before_exit();
    return 0;
}
