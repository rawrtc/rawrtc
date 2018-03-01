#include <stdlib.h> // exit
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "data-channel-sctp-loopback-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// Note: Shadows struct client
struct data_channel_sctp_client {
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
    struct rawrtc_data_transport* data_transport;
    struct data_channel_helper* data_channel_negotiated;
    struct data_channel_helper* data_channel;
    struct data_channel_sctp_client* other_client;
};

static struct tmr timer = {{0}};

static void timer_handler(
        void* arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;
    enum rawrtc_dtls_role role;

    // Compose message (16 MiB)
    buffer = mbuf_alloc(1 << 24);
    EOE(buffer ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_NO_MEMORY);
    EOR(mbuf_fill(buffer, 'M', mbuf_get_space(buffer)));
    mbuf_set_pos(buffer, 0);

    // Send message
    DEBUG_PRINTF("(%s) Sending %zu bytes\n", client->name, mbuf_get_left(buffer));
    error = rawrtc_data_channel_send(channel->channel, buffer, true);
    if (error) {
        DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
    }
    mem_deref(buffer);

    // Get DTLS role
    EOE(rawrtc_dtls_parameters_get_role(&role, client->dtls_parameters));
    if (role == RAWRTC_DTLS_ROLE_CLIENT) {
        // Close bear-noises
        DEBUG_PRINTF("(%s) Closing channel\n", client->name, channel->label);
        EOR(rawrtc_data_channel_close(client->data_channel->channel));
    }
}

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;

    // Print open event
    default_data_channel_open_handler(arg);

    // Send data delayed on bear-noises
    if (str_cmp(channel->label, "bear-noises") == 0) {
        tmr_start(&timer, 1000, timer_handler, channel);
        return;
    }

    // Compose message (256 KiB)
    buffer = mbuf_alloc(1 << 18);
    EOE(buffer ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_NO_MEMORY);
    EOR(mbuf_fill(buffer, 'M', mbuf_get_space(buffer)));
    mbuf_set_pos(buffer, 0);

    // Send message
    DEBUG_PRINTF("(%s) Sending %zu bytes\n", client->name, mbuf_get_left(buffer));
    error = rawrtc_data_channel_send(channel->channel, buffer, true);
    if (error) {
        DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
    }
    mem_deref(buffer);
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct data_channel_sctp_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Add to other client as remote candidate (if type enabled)
    add_to_other_if_ice_candidate_type_enabled(
            arg, candidate, client->other_client->ice_transport);
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct data_channel_sctp_client* const client = arg;

    // Print state
    default_dtls_transport_state_change_handler(state, arg);

    // Open? Create new data channel
    // TODO: Move this once we can create data channels earlier
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        enum rawrtc_dtls_role role;

        // Renew DTLS parameters
        mem_deref(client->dtls_parameters);
        EOE(rawrtc_dtls_transport_get_local_parameters(
                &client->dtls_parameters, client->dtls_transport));

        // Get DTLS role
        EOE(rawrtc_dtls_parameters_get_role(&role, client->dtls_parameters));
        DEBUG_PRINTF("(%s) DTLS role: %s\n", client->name, rawrtc_dtls_role_to_str(role));

        // Client? Create data channel
        if (role == RAWRTC_DTLS_ROLE_CLIENT) {
            struct rawrtc_data_channel_parameters* channel_parameters;
            
            // Create data channel helper
            data_channel_helper_create(
                    &client->data_channel, (struct client *) client, "bear-noises");

            // Create data channel parameters
            EOE(rawrtc_data_channel_parameters_create(
                    &channel_parameters, client->data_channel->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0));

            // Create data channel
            EOE(rawrtc_data_channel_create(
                    &client->data_channel->channel, client->data_transport,
                    channel_parameters, NULL,
                    data_channel_open_handler,
                    default_data_channel_buffered_amount_low_handler,
                    default_data_channel_error_handler, default_data_channel_close_handler,
                    default_data_channel_message_handler, client->data_channel));

            // Un-reference
            mem_deref(channel_parameters);
        }
    }
}

static void client_init(
        struct data_channel_sctp_client* const local
) {
    struct rawrtc_certificate* certificates[1];
    struct rawrtc_data_channel_parameters* channel_parameters;

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
            &local->dtls_transport, local->ice_transport, certificates, ARRAY_SIZE(certificates),
            dtls_transport_state_change_handler, default_dtls_transport_error_handler, local));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &local->sctp_transport, local->dtls_transport, local->sctp_port,
            default_data_channel_handler, default_sctp_transport_state_change_handler, local));

    // Get SCTP capabilities
    EOE(rawrtc_sctp_transport_get_capabilities(&local->sctp_capabilities));

    // Get data transport
    EOE(rawrtc_sctp_transport_get_data_transport(
            &local->data_transport, local->sctp_transport));

    // Create data channel helper
    data_channel_helper_create(
            &local->data_channel_negotiated, (struct client *) local, "cat-noises");

    // Create data channel parameters
    EOE(rawrtc_data_channel_parameters_create(
            &channel_parameters, local->data_channel_negotiated->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0));

    // Create pre-negotiated data channel
    EOE(rawrtc_data_channel_create(
            &local->data_channel_negotiated->channel, local->data_transport,
            channel_parameters, NULL,
            data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            default_data_channel_message_handler, local->data_channel_negotiated));

    // Un-reference
    mem_deref(channel_parameters);
}

static void client_start(
        struct data_channel_sctp_client* const local,
        struct data_channel_sctp_client* const remote
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
        struct data_channel_sctp_client* const client
) {
    // Stop transports & close gatherer
    if (client->data_channel) {
        EOE(rawrtc_data_channel_close(client->data_channel->channel));
    }
    EOE(rawrtc_data_channel_close(client->data_channel_negotiated->channel));
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Un-reference & close
    client->data_channel = mem_deref(client->data_channel);
    client->data_channel_negotiated = mem_deref(client->data_channel_negotiated);
    client->sctp_capabilities = mem_deref(client->sctp_capabilities);
    client->dtls_parameters = mem_deref(client->dtls_parameters);
    client->ice_parameters = mem_deref(client->ice_parameters);
    client->data_transport = mem_deref(client->data_transport);
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
    struct data_channel_sctp_client a = {0};
    struct data_channel_sctp_client b = {0};
    (void) a.ice_candidate_types; (void) a.n_ice_candidate_types;
    (void) b.ice_candidate_types; (void) b.n_ice_candidate_types;

    // Initialise
    EOE(rawrtc_init(true));

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
            gather_options, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_threema_ch_urls, ARRAY_SIZE(turn_threema_ch_urls),
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

    // Listen on stdin
    EOR(fd_listen(STDIN_FILENO, FD_READ, stop_on_return_handler, NULL));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);

    // Free
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
