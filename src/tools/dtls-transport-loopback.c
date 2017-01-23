#include <rawrtc.h>
#include "../librawrtc/dtls_transport.h" /* TODO: Replace with <rawrtc_internal/dtls_transport.h> */
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "dtls-transport-loopback-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// Note: Shadows struct client
struct dtls_transport_client {
    char* name;
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct dtls_transport_client* other_client;
};

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct dtls_transport_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Add to other client as remote candidate
    EOE(rawrtc_ice_transport_add_remote_candidate(client->other_client->ice_transport, candidate));
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct dtls_transport_client* const client = arg;

    // Print state
    default_dtls_transport_state_change_handler(state, arg);

    // Open? Send message (twice to test the buffering)
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING ||
            state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        enum rawrtc_code error;

        // Send message
        struct mbuf* buffer = mbuf_alloc(1024);
        mbuf_printf(buffer, "Hello! Meow meow meow meow meow meow meow meow meow!");
        mbuf_set_pos(buffer, 0);
        DEBUG_PRINTF("Sending %zu bytes: %b\n", mbuf_get_left(buffer), mbuf_buf(buffer),
                     mbuf_get_left(buffer));
        error = rawrtc_dtls_transport_send(client->dtls_transport, buffer);
        if (error) {
            DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
        }
        mem_deref(buffer);
    }
}

static void client_init(
        struct dtls_transport_client* const local
) {
    struct rawrtc_certificate* certificates[1];

    // Generate certificates
    EOE(rawrtc_certificate_generate(&local->certificate, NULL));
    certificates[0] = local->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &local->gatherer, local->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, local));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &local->dtls_transport, local->ice_transport, certificates,
            sizeof(certificates) / sizeof(certificates[0]),
            dtls_transport_state_change_handler, default_dtls_transport_error_handler, local));
}

static void client_start(
        struct dtls_transport_client* const local,
        struct dtls_transport_client* const remote
) {
    // Get & set ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local->ice_parameters, remote->gatherer));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(local->gatherer, NULL));

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            local->ice_transport, local->gatherer, local->ice_parameters, local->role));

    // Get & set DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &local->dtls_parameters, remote->dtls_transport));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            local->dtls_transport, local->dtls_parameters));
}

static void client_stop(
        struct dtls_transport_client* const client
) {
    // Stop transports & close gatherer
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->dtls_parameters = mem_deref(client->dtls_parameters);
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct dtls_transport_client a = {0};
    struct dtls_transport_client b = {0};

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

    // Setup client A
    a.name = "A";
    a.gather_options = gather_options;
    a.role = RAWRTC_ICE_ROLE_CONTROLLING;
    a.other_client = &b;

    // Setup client B
    b.name = "B";
    b.gather_options = gather_options;
    b.role = RAWRTC_ICE_ROLE_CONTROLLED;
    b.other_client = &a;

    // Initialise clients
    client_init(&a);
    client_init(&b);

    // Start clients
    client_start(&a, &b);
    client_start(&b, &a);

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
