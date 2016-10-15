#include <stdio.h>
#include <stdint.h> // uint16t, ...
#include <inttypes.h> // PRIu16, ...
#include <anyrtc.h>

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "ice-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EOE(code) exit_on_error(code, __FILE__, __LINE__)

struct client;

struct client {
    char* name;
    struct anyrtc_ice_gather_options* gather_options;
    struct anyrtc_ice_parameters* remote_parameters;
    enum anyrtc_ice_role const role;
    struct anyrtc_ice_gatherer* gatherer;
    struct anyrtc_ice_transport* ice_transport;
    struct client* other_client;
};

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
    struct client* const client = arg;
    char const * const state_name = anyrtc_ice_gatherer_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer state: %s\n", client->name, state_name);
}

static void ice_gatherer_error_handler(
        struct anyrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

static void ice_gatherer_local_candidate_handler(
        struct anyrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) candidate; (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer local candidate, URL: %s\n", client->name, url);

    // Add to other client as remote candidate
    if (candidate) {
        EOE(anyrtc_ice_transport_add_remote_candidate(
                client->other_client->ice_transport, candidate));
    } else {
        DEBUG_PRINTF("(%s) ICE gatherer last candidate\n", client->name);
    }
}

static void ice_transport_state_change_handler(
        enum anyrtc_ice_transport_state const state,
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = anyrtc_ice_transport_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE transport state: %s\n", client->name, state_name);
}

static void ice_transport_candidate_pair_change_handler(
        struct anyrtc_ice_candidate* const local, // read-only
        struct anyrtc_ice_candidate* const remote, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) local; (void) remote;
    DEBUG_PRINTF("(%s) ICE transport candidate pair change\n", client->name);
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

struct anyrtc_ice_parameters* client_init(
        struct client* const client
) {
    struct anyrtc_ice_parameters* local_parameters;

    // Create ICE gatherer
    EOE(anyrtc_ice_gatherer_create(
            &client->gatherer, client->gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, client));

    // Create ICE transport
    EOE(anyrtc_ice_transport_create(
            &client->ice_transport, client->gatherer,
            ice_transport_state_change_handler, ice_transport_candidate_pair_change_handler,
            client));

    // Get and return local parameters
    EOE(anyrtc_ice_gatherer_get_local_parameters(client->gatherer, &local_parameters));
    return local_parameters;
}

void client_start(
        struct client* const client
) {
    // Start gathering & transport
    EOE(anyrtc_ice_gatherer_gather(client->gatherer, NULL));
    EOE(anyrtc_ice_transport_start(
            client->ice_transport, client->gatherer, client->remote_parameters, client->role));
}

void client_stop(
        struct client* const client
) {
    // Stop transport & close gatherer
    EOE(anyrtc_ice_transport_stop(client->ice_transport));
    EOE(anyrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
}

int main(int argc, char* argv[argc + 1]) {
    struct anyrtc_ice_gather_options* gather_options;
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
            sizeof(stun_google_com_urls) / sizeof(char *),
            NULL, NULL, ANYRTC_ICE_CREDENTIAL_NONE));
    EOE(anyrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org_urls) / sizeof(char *),
            "bruno", "onurb", ANYRTC_ICE_CREDENTIAL_PASSWORD));

    // Start clients
    struct client a = {"A", gather_options, NULL, ANYRTC_ICE_ROLE_CONTROLLING, NULL, NULL};
    struct client b = {"B", gather_options, NULL, ANYRTC_ICE_ROLE_CONTROLLED, NULL, NULL};
    a.other_client = &b;
    b.other_client = &a;
    b.remote_parameters = client_init(&a);
    a.remote_parameters = client_init(&b);
    client_start(&a);
    client_start(&b);

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(anyrtc_translate_re_code(re_main(signal_handler)));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(a.remote_parameters);
    mem_deref(b.remote_parameters);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
