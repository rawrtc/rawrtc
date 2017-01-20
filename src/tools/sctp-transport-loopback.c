#include <stdio.h>
#include <rawrtc.h>
#include <usrsctp.h> // sctp_sendv_spa
#include "../librawrtc/sctp_transport.h" /* TODO: Replace with <rawrtc_internal/sctp_transport.h> */
#include "../librawrtc/utils.h" /* TODO: Replace with <rawrtc_internal/utils.h> */

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "sctp-transport-loopback-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct client;

struct client {
    char* name;
    struct rawrtc_ice_gather_options* gather_options;
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct rawrtc_sctp_capabilities* sctp_capabilities;
    enum rawrtc_ice_role const role;
    struct rawrtc_certificate* certificate;
    uint16_t sctp_port;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct client* other_client;
};

static void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_gatherer_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer state: %s\n", client->name, state_name);
}

static void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
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
        struct rawrtc_ice_candidate* const candidate,
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
    EOE(rawrtc_ice_transport_add_remote_candidate(client->other_client->ice_transport, candidate));
}

static void ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_transport_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE transport state: %s\n", client->name, state_name);
}

static void ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) local; (void) remote;
    DEBUG_PRINTF("(%s) ICE transport candidate pair change\n", client->name);
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_dtls_transport_state_to_name(state);
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

static void sctp_transport_state_change_handler(
    enum rawrtc_sctp_transport_state const state,
    void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_sctp_transport_state_to_name(state);
    DEBUG_PRINTF("(%s) SCTP transport state change: %s\n", client->name, state_name);

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

static struct rawrtc_data_channel_options* data_channel_handler(
        struct rawrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
        void* const arg
) {
    struct client* const client = arg;
    DEBUG_PRINTF("(%s) New data channel instance\n", client->name);
    return NULL; // Use default options
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

static void client_init(
        struct client* const local
) {
    // Generate certificates
    EOE(rawrtc_certificate_generate(&local->certificate, NULL));
    struct rawrtc_certificate* certificates[] = {local->certificate};

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &local->gatherer, local->gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, local));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &local->ice_transport, local->gatherer,
            ice_transport_state_change_handler, ice_transport_candidate_pair_change_handler,
            local));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &local->dtls_transport, local->ice_transport, certificates,
            sizeof(certificates) / sizeof(certificates[0]),
            dtls_transport_state_change_handler, dtls_transport_error_handler, local));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &local->sctp_transport, local->dtls_transport, local->sctp_port,
            data_channel_handler, sctp_transport_state_change_handler, local));
}

static void client_start(
        struct client* const local,
        struct client* const remote
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

    // Get SCTP capabilities
    EOE(rawrtc_sctp_transport_get_capabilities(
            &remote->sctp_capabilities, remote->sctp_transport));

    // Start SCTP transport
    EOE(rawrtc_sctp_transport_start(
            local->sctp_transport, remote->sctp_capabilities));
}

static void client_stop(
        struct client* const client
) {
    // Stop transports & close gatherer
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    client->sctp_capabilities = mem_deref(client->sctp_capabilities);
    client->dtls_parameters = mem_deref(client->dtls_parameters);
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
}

int main(int argc, char* argv[argc + 1]) {
    struct rawrtc_ice_gather_options* gather_options;
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

    // Initialise clients
    struct client a = {
            .name = "A",
            .gather_options = gather_options,
            .ice_parameters = NULL,
            .dtls_parameters = NULL,
            .role = RAWRTC_ICE_ROLE_CONTROLLING,
            .certificate = NULL,
            .sctp_port = 6000,
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
            .role = RAWRTC_ICE_ROLE_CONTROLLED,
            .certificate = NULL,
            .sctp_port = 5000,
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
    EOE(rawrtc_error_to_code(re_main(signal_handler)));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(gather_options);

    // Bye
    rawrtc_before_exit();
    return 0;
}
