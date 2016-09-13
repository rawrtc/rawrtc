#include <anyrtc.h>

int main(int argc, char* argv[argc + 1]) {
    struct anyrtc_ice_gather_options* gather_options;

    // Initialise
    anyrtc_init();

    // Create ICE gather options
    anyrtc_ice_gather_options_create(&gather_options, ANYRTC_ICE_GATHER_ALL);

    // Dereference & close
    mem_deref(gather_options);
    anyrtc_close();

    // Check memory leaks
    tmr_debug();
    mem_debug();
}
