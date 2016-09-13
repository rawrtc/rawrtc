#include <stdio.h>
#include <stdint.h> // uint16t, ...
#include <inttypes.h> // PRIu16, ...
#include <anyrtc.h>

#define EOR(code) exit_on_error(code, __FILE__, __LINE__)

static void before_exit() {
    // Close
    anyrtc_close();

    // Check memory leaks
    tmr_debug();
    mem_debug();
}

static void exit_on_error(enum anyrtc_code code, char const* const file, uint32_t line) {
    if (code != 0) {
        fprintf(stderr, "Error in %s %"PRIu32" (%d): NO TRANSLATION\n",
                file, line, code);
        before_exit();
        exit((int) code);
    }
}

int main(int argc, char* argv[argc + 1]) {
    struct anyrtc_ice_server* stun_google_com;
    struct anyrtc_ice_server* turn_zwuenf_org;
    struct anyrtc_ice_gather_options* gather_options;

    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};

    // Initialise
    EOR(anyrtc_init());

    // Create ICE servers
    EOR(anyrtc_ice_server_create(
            &stun_google_com, stun_google_com_urls,
            sizeof(stun_google_com_urls) / sizeof(char *),
            NULL, NULL, ANYRTC_ICE_CREDENTIAL_NONE));
    EOR(anyrtc_ice_server_create(
            &turn_zwuenf_org, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org) / sizeof(char *),
            "bruno", "onurb", ANYRTC_ICE_CREDENTIAL_PASSWORD));

    // Create ICE gather options
    EOR(anyrtc_ice_gather_options_create(&gather_options, ANYRTC_ICE_GATHER_ALL));

    // Dereference & close
    mem_deref(turn_zwuenf_org);
    mem_deref(stun_google_com);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
