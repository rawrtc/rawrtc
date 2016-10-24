#include <stdio.h>
#include <anyrtc.h>

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "redirect-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EOE(code) exit_on_error(code, __FILE__, __LINE__)

struct parameters {
    struct anyrtc_ice_parameters* ice_parameters;
    struct anyrtc_dtls_parameters* dtls_parameters;
};

struct client {
    char* name;
    struct anyrtc_ice_gather_options* gather_options;
    struct anyrtc_certificate* certificate;
    struct anyrtc_ice_gatherer* gatherer;
    struct anyrtc_ice_transport* ice_transport;
    struct anyrtc_dtls_transport* dtls_transport;
    struct anyrtc_sctp_transport* redirect_transport;
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
            fprintf(stderr, "Error in %s %"PRIu32" (%d): %s\n",
                    file, line, code, anyrtc_code_to_str(code));
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

    if (candidate) {
        DEBUG_PRINTF("(%s) ICE gatherer local candidate, URL: %s\n", client->name, url);
    } else {
        DEBUG_PRINTF("(%s) ICE gatherer last local candidate\n", client->name);
    }

    // Add to other client as remote candidate
    EOE(anyrtc_ice_transport_add_remote_candidate(client->other_client->ice_transport, candidate));
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

static void dtls_transport_state_change_handler(
        enum anyrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = anyrtc_dtls_transport_state_to_name(state);
    DEBUG_PRINTF("(%s) DTLS transport state change: %s\n", client->name, state_name);
}

static void dtls_transport_error_handler(
        /* TODO: error.message (probably from OpenSSL) */
        void* const arg
) {
    struct client* const client = arg;
    // TODO: Print error message
    DEBUG_PRINTF("(%s) DTLS transport error: %s\n", client->name, "???");
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

void client_init(
        struct client* const client,
        struct parameters* const local_parameters
) {
    // Generate certificates
    EOE(anyrtc_certificate_generate(&client->certificate, NULL));
    struct anyrtc_certificate* certificates[] = {client->certificate};

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

    // Create DTLS transport
    EOE(anyrtc_dtls_transport_create(
            &client->dtls_transport, client->ice_transport, certificates,
            sizeof(certificates) / sizeof(struct anyrtc_certificate*),
            dtls_transport_state_change_handler, dtls_transport_error_handler, client));

    // Create redirect transport
    EOE(anyrtc_redirect_transport_create(
            &client->redirect_transport, client->dtls_transport, 0, data_channel_handler, client));

    // Get ICE parameters
    EOE(anyrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, client->gatherer));

    // Get DTLS parameters
    EOE(anyrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, client->dtls_transport));
}

void client_start(
        struct client* const client,
        struct parameters* const remote_parameters,
        enum anyrtc_ice_role const local_role
) {
    // Start gathering
    EOE(anyrtc_ice_gatherer_gather(client->gatherer, NULL));

    // Start ICE transport
    EOE(anyrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters, local_role));

    // Start DTLS transport
    EOE(anyrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters));
}

void exchange_parameters(
        struct parameters* const local_parameters,
        struct parameters* const remote_parameters,
        enum anyrtc_ice_role* const local_role
) {
    // TODO
}

void client_stop(
        struct client* const client
) {
    // Stop transports & close gatherer
//    EOE(anyrtc_redirect_transport_stop(client->redirect_transport));
    EOE(anyrtc_dtls_transport_stop(client->dtls_transport));
    EOE(anyrtc_ice_transport_stop(client->ice_transport));
    EOE(anyrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->redirect_transport = mem_deref(client->redirect_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
}

void free_parameters(
        struct parameters* const parameters
) {
    mem_deref(parameters->dtls_parameters);
    mem_deref(parameters->ice_parameters);
}

int main(int argc, char* argv[argc + 1]) {
    struct anyrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct parameters local_parameters;
    struct parameters remote_parameters;
    enum anyrtc_ice_role role;

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

    // Initialise client & retrieve local parameters
    struct client client = {
            .name = "A",
            .gather_options = gather_options,
            .certificate = NULL,
            .gatherer = NULL,
            .ice_transport = NULL,
            .dtls_transport = NULL,
            .redirect_transport = NULL,
    };
    client_init(&client, &local_parameters);

    // Exchange parameters (and role)
    exchange_parameters(&local_parameters, &remote_parameters, &role);

    // Start client
    client_start(&client, &remote_parameters, role);

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(anyrtc_translate_re_code(re_main(signal_handler)));

    // Stop client
    client_stop(&client);

    // Free
    free_parameters(&local_parameters);
    free_parameters(&remote_parameters);
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
