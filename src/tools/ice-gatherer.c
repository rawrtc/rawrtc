#include <stdio.h>
#include <anyrtc.h>

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "ice-gatherer-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EOE(code) exit_on_error(code, __FILE__, __LINE__)

static void before_exit() {
    // Close
    anyrtc_close();

    // Check memory leaks
    tmr_debug();
    mem_debug();
}

static void exit_on_error(enum anyrtc_code code, char const* const file, uint32_t line) {
    switch (code) {
        case ANYRTC_CODE_SUCCESS:
            return;
        case ANYRTC_CODE_NOT_IMPLEMENTED:
            fprintf(stderr, "Not implemented in %s %"PRIu32"\n",
                    file, line);
            return;
        default:
            fprintf(stderr, "Error in %s %"PRIu32" (%d): NO TRANSLATION\n",
                    file, line, code);
            before_exit();
            exit((int) code);
    }
}

static void ice_gatherer_state_change_handler(
        enum anyrtc_ice_gatherer_state const state, // read-only
        void* const arg
) {
    (void) arg;
    DEBUG_PRINTF("ICE gatherer state: %s\n", anyrtc_ice_gatherer_state_to_name(state));
}

static void ice_gatherer_error_handler(
        struct anyrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg
) {
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_PRINTF("ICE gatherer error, URL: %s, reason: %s\n", url, error_text);
}

static void ice_gatherer_local_candidate_handler(
        struct anyrtc_ice_candidate* const candidate,
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
    struct anyrtc_ice_gather_options* gather_options;
    struct anyrtc_ice_gatherer* gatherer;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};

    // Initialise
    EOE(anyrtc_init());

    // Debug
    // TODO: This should be replaced by our own debugging system
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Create ICE gather options
    EOE(anyrtc_ice_gather_options_create(&gather_options, ANYRTC_ICE_GATHER_ALL));

    // Add ICE servers to ICE gather options
    EOE(anyrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls,
            sizeof(stun_google_com_urls) / sizeof(char*),
            NULL, NULL, ANYRTC_ICE_CREDENTIAL_NONE));
    EOE(anyrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org_urls) / sizeof(char*),
            "bruno", "onurb", ANYRTC_ICE_CREDENTIAL_PASSWORD));

    // Create ICE gatherer
    EOE(anyrtc_ice_gatherer_create(
            &gatherer, gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, NULL));

    // Start gathering
    EOE(anyrtc_ice_gatherer_gather(gatherer, NULL));

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(anyrtc_translate_re_code(re_main(signal_handler)));

    // Close gatherer
    EOE(anyrtc_ice_gatherer_close(gatherer));

    // Dereference & close
    mem_deref(gatherer);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
