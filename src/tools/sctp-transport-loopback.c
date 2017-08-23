#include <rawrtc.h>
#include "../librawrtc/sctp_transport.h" /* TODO: Replace with <rawrtc_internal/sctp_transport.h> */
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "sctp-transport-loopback-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// Note: Shadows struct client
struct sctp_transport_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct rawrtc_sctp_capabilities* sctp_capabilities;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    uint16_t sctp_port;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct sctp_transport_client* other_client;
};

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct sctp_transport_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Add to other client as remote candidate (if type enabled)
    add_to_other_if_ice_candidate_type_enabled(
            arg, candidate, client->other_client->ice_transport);
}

static void sctp_transport_state_change_handler(
    enum rawrtc_sctp_transport_state const state,
    void* const arg
) {
    struct sctp_transport_client* const client = arg;

    // Print state
    default_sctp_transport_state_change_handler(state, arg);

    // Open? Send message (twice to test the buffering)
    if (state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTED ||
            state == RAWRTC_SCTP_TRANSPORT_STATE_CONNECTING) {
        struct sctp_sendv_spa spa = {0};
        enum rawrtc_code error;

        // Compose meowing message
        struct mbuf* buffer = mbuf_alloc(1024);
        mbuf_printf(buffer, "Hello! Meow meow meow meow meow meow meow meow meow!");
        mbuf_set_pos(buffer, 0);

        // Set SCTP stream, protocol identifier and flags
        spa.sendv_sndinfo.snd_sid = 0;
        spa.sendv_sndinfo.snd_flags = SCTP_EOR;
        spa.sendv_sndinfo.snd_ppid = htonl(RAWRTC_SCTP_TRANSPORT_PPID_DCEP);
        spa.sendv_flags = SCTP_SEND_SNDINFO_VALID;

        // Send message
        DEBUG_PRINTF("Sending %zu bytes: %b\n", mbuf_get_left(buffer), mbuf_buf(buffer),
                     mbuf_get_left(buffer));
        error = rawrtc_sctp_transport_send(
                client->sctp_transport, buffer, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
        if (error) {
            DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
        }
        mem_deref(buffer);
    }
}

static void client_init(
        struct sctp_transport_client* const local
) {
    struct rawrtc_certificate* certificates[1];

    // Generate certificates
    EOE(rawrtc_certificate_generate(&local->certificate, NULL));
    certificates[0] = local->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &local->gatherer, NULL, local->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, local));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &local->dtls_transport, local->ice_transport, certificates, ARRAY_SIZE(certificates),
            default_dtls_transport_state_change_handler, default_dtls_transport_error_handler,
            local));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &local->sctp_transport, local->dtls_transport, local->sctp_port,
            default_data_channel_handler, sctp_transport_state_change_handler, local));

    // Get SCTP capabilities
    EOE(rawrtc_sctp_transport_get_capabilities(&local->sctp_capabilities));
}

static void client_start(
        struct sctp_transport_client* const local,
        struct sctp_transport_client* const remote
) {
    // Get & set ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local->ice_parameters, remote->gatherer));

    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(local->gatherer, NULL));

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            local->ice_transport, local->gatherer, local->ice_parameters, local->role));

    // Get DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &remote->dtls_parameters, remote->dtls_transport));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            local->dtls_transport, remote->dtls_parameters));

    // Start SCTP transport
    EOE(rawrtc_sctp_transport_start(
            local->sctp_transport, remote->sctp_capabilities, remote->sctp_port));
}

static void client_stop(
        struct sctp_transport_client* const client
) {
    // Stop transports & close gatherer
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Un-reference & close
    client->sctp_capabilities = mem_deref(client->sctp_capabilities);
    client->dtls_parameters = mem_deref(client->dtls_parameters);
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s [<ice-candidate-type> ...]", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
    char* const turn_threema_ch_urls[] = {"turn:turn.threema.ch:443"};
    struct sctp_transport_client a = {0};
    struct sctp_transport_client b = {0};
    (void) a.ice_candidate_types; (void) a.n_ice_candidate_types;
    (void) b.ice_candidate_types; (void) b.n_ice_candidate_types;

    // Initialise
    EOE(rawrtc_init());

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Get enabled ICE candidate types to be added (optional)
    if (argc > 1) {
        ice_candidate_types = &argv[1];
        n_ice_candidate_types = (size_t) argc - 1;
    }

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL));

    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, NULL, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, NULL, turn_threema_ch_urls, ARRAY_SIZE(turn_threema_ch_urls),
            "threema-angular", "Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
            RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD));

    // Setup client A
    a.name = "A";
    a.ice_candidate_types = ice_candidate_types;
    a.n_ice_candidate_types = n_ice_candidate_types;
    a.gather_options = gather_options;
    a.role = RAWRTC_ICE_ROLE_CONTROLLING;
    a.sctp_port = 6000;
    a.other_client = &b;

    // Setup client B
    b.name = "B";
    b.ice_candidate_types = ice_candidate_types;
    b.n_ice_candidate_types = n_ice_candidate_types;
    b.gather_options = gather_options;
    b.role = RAWRTC_ICE_ROLE_CONTROLLED;
    b.sctp_port = 5000;
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
