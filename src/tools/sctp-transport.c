#include <stdio.h>
#include <anyrtc.h>

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "sctp-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EOE(code) exit_on_error(code, __FILE__, __LINE__)

struct client;

struct client {
    char* name;
    struct anyrtc_ice_gather_options* gather_options;
    struct anyrtc_ice_parameters* ice_parameters;
    struct anyrtc_dtls_parameters* dtls_parameters;
    enum anyrtc_ice_role const role;
    struct anyrtc_certificate* certificate;
    struct anyrtc_ice_gatherer* gatherer;
    struct anyrtc_ice_transport* ice_transport;
    struct anyrtc_dtls_transport* dtls_transport;
    struct anyrtc_sctp_transport* sctp_transport;
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

    // Open? Send message
    if (state == ANYRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        // Send message
        struct mbuf* buffer = mbuf_alloc(1024);
        mbuf_printf(buffer, "Hello! Meow meow meow meow meow meow meow meow meow!");
        mbuf_set_pos(buffer, 0);
        DEBUG_PRINTF("Sending %zu bytes: %b\n", mbuf_get_left(buffer), mbuf_buf(buffer),
                     mbuf_get_left(buffer));
        int error = dtls_send(client->dtls_transport->connection, buffer);
        if (error) {
            DEBUG_WARNING("Could not send, error: %m\n", error);
        }
        mem_deref(buffer);
    }
}

static void dtls_transport_error_handler(
    /* TODO: error.message (probably from OpenSSL) */
    void* const arg
) {
    struct client* const client = arg;
    // TODO: Print error message
    DEBUG_PRINTF("(%s) DTLS transport error: %s\n", client->name, "???");
}

void data_channel_handler(
        struct anyrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
        void* const arg
) {
    struct client* const client = arg;
    DEBUG_PRINTF("(%s) New data channel instance\n", client->name);
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

void client_init(
        struct client* const local
) {
    // Generate certificates
    EOE(anyrtc_certificate_generate(&local->certificate, NULL));
    struct anyrtc_certificate* certificates[] = {local->certificate};

    // Create ICE gatherer
    EOE(anyrtc_ice_gatherer_create(
            &local->gatherer, local->gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local));

    // Create ICE transport
    EOE(anyrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            ice_transport_state_change_handler, ice_transport_candidate_pair_change_handler,
            local));

    // Create DTLS transport
    EOE(anyrtc_dtls_transport_create(
            &local->dtls_transport, local->ice_transport, certificates,
            sizeof(certificates) / sizeof(struct anyrtc_certificate*),
            dtls_transport_state_change_handler, dtls_transport_error_handler, local));

    // Create SCTP transport
    EOE(anyrtc_sctp_transport_create(
            &local->sctp_transport, local->dtls_transport, 0, data_channel_handler, local));
}

void client_start(
        struct client* const local,
        struct client* const remote
) {
    // Get & set ICE parameters
    EOE(anyrtc_ice_gatherer_get_local_parameters(&local->ice_parameters, remote->gatherer));

    // Start gathering
    EOE(anyrtc_ice_gatherer_gather(local->gatherer, NULL));

    // Start ICE transport
    EOE(anyrtc_ice_transport_start(
            local->ice_transport, local->gatherer, local->ice_parameters, local->role));

    // Get & set DTLS parameters
    EOE(anyrtc_dtls_transport_get_local_parameters(
            &local->dtls_parameters, remote->dtls_transport));

    // Start DTLS transport
    EOE(anyrtc_dtls_transport_start(
            local->dtls_transport, local->dtls_parameters));
}

void client_stop(
        struct client* const client
) {
    // Stop transports & close gatherer
//    EOE(anyrtc_sctp_transport_stop(client->sctp_transport));
    EOE(anyrtc_dtls_transport_stop(client->dtls_transport));
    EOE(anyrtc_ice_transport_stop(client->ice_transport));
    EOE(anyrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->dtls_parameters = mem_deref(client->dtls_parameters);
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
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
            sizeof(stun_google_com_urls) / sizeof(char*),
            NULL, NULL, ANYRTC_ICE_CREDENTIAL_NONE));
    EOE(anyrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org_urls) / sizeof(char*),
            "bruno", "onurb", ANYRTC_ICE_CREDENTIAL_PASSWORD));

    // Initialise clients
    struct client a = {
            .name = "A",
            .gather_options = gather_options,
            .ice_parameters = NULL,
            .dtls_parameters = NULL,
            .role = ANYRTC_ICE_ROLE_CONTROLLING,
            .certificate = NULL,
            .gatherer = NULL,
            .ice_transport = NULL,
            .dtls_transport = NULL,
            .sctp_transport = NULL,
            .other_client = NULL,
    };
    struct client b = {
            .name = "B",
            .gather_options = gather_options,
            .ice_parameters = NULL,
            .dtls_parameters = NULL,
            .role = ANYRTC_ICE_ROLE_CONTROLLED,
            .certificate = NULL,
            .gatherer = NULL,
            .ice_transport = NULL,
            .dtls_transport = NULL,
            .sctp_transport = NULL,
            .other_client = NULL,
    };
    a.other_client = &b;
    b.other_client = &a;
    client_init(&a);
    client_init(&b);

    // Start clients
    client_start(&a, &b);
    client_start(&b, &a);

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(anyrtc_translate_re_code(re_main(signal_handler)));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
