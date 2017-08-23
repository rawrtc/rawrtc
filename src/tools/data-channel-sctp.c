#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "data-channel-sctp-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

// Note: Shadows struct client
struct data_channel_sctp_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct data_channel_helper* data_channel_negotiated;
    struct data_channel_helper* data_channel;
    struct parameters local_parameters;
    struct parameters remote_parameters;
};

static void print_local_parameters(
    struct data_channel_sctp_client *client
);

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

    // Compose message (16 KiB)
    buffer = mbuf_alloc(1 << 14);
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
    EOE(rawrtc_dtls_parameters_get_role(&role, client->local_parameters.dtls_parameters));
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
        tmr_start(&timer, 30000, timer_handler, channel);
        return;
    }

    // Compose message (8 KiB)
    buffer = mbuf_alloc(1 << 13);
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

    // Print local parameters (if last candidate)
    if (!candidate) {
        print_local_parameters(client);
    }
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
        mem_deref(client->local_parameters.dtls_parameters);
        EOE(rawrtc_dtls_transport_get_local_parameters(
                &client->local_parameters.dtls_parameters, client->dtls_transport));

        // Get DTLS role
        EOE(rawrtc_dtls_parameters_get_role(&role, client->local_parameters.dtls_parameters));
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
        struct data_channel_sctp_client* const client
) {
    struct rawrtc_certificate* certificates[1];
    struct rawrtc_data_channel_parameters* channel_parameters;

    // Generate certificates
    EOE(rawrtc_certificate_generate(&client->certificate, NULL));
    certificates[0] = client->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &client->gatherer, NULL, client->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, client));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &client->ice_transport, client->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, client));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &client->dtls_transport, client->ice_transport, certificates, ARRAY_SIZE(certificates),
            dtls_transport_state_change_handler, default_dtls_transport_error_handler, client));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &client->sctp_transport, client->dtls_transport,
            client->local_parameters.sctp_parameters.port,
            default_data_channel_handler, default_sctp_transport_state_change_handler, client));

    // Get data transport
    EOE(rawrtc_sctp_transport_get_data_transport(
            &client->data_transport, client->sctp_transport));

    // Create data channel helper
    data_channel_helper_create(
            &client->data_channel_negotiated, (struct client *) client, "cat-noises");

    // Create data channel parameters
    EOE(rawrtc_data_channel_parameters_create(
            &channel_parameters, client->data_channel_negotiated->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0));

    // Create pre-negotiated data channel
    EOE(rawrtc_data_channel_create(
            &client->data_channel_negotiated->channel, client->data_transport,
            channel_parameters, NULL,
            data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            default_data_channel_message_handler, client->data_channel_negotiated));

    // Un-reference
    mem_deref(channel_parameters);
}

static void client_start_gathering(
        struct data_channel_sctp_client* const client
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(client->gatherer, NULL));
}

static void client_start_transports(
        struct data_channel_sctp_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters,
            client->role));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters));

    // Start SCTP transport
    EOE(rawrtc_sctp_transport_start(
            client->sctp_transport, remote_parameters->sctp_parameters.capabilities,
            remote_parameters->sctp_parameters.port));
}

static void parameters_destroy(
        struct parameters* const parameters
) {
    // Un-reference
    parameters->ice_parameters = mem_deref(parameters->ice_parameters);
    parameters->ice_candidates = mem_deref(parameters->ice_candidates);
    parameters->dtls_parameters = mem_deref(parameters->dtls_parameters);
    if (parameters->sctp_parameters.capabilities) {
        parameters->sctp_parameters.capabilities =
                mem_deref(parameters->sctp_parameters.capabilities);
    }
}

static void client_stop(
        struct data_channel_sctp_client* const client
) {
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Un-reference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->data_channel = mem_deref(client->data_channel);
    client->data_channel_negotiated = mem_deref(client->data_channel_negotiated);
    client->data_transport = mem_deref(client->data_transport);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);
}

static void client_set_parameters(
        struct data_channel_sctp_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Set remote ICE candidates
    EOE(rawrtc_ice_transport_set_remote_candidates(
            client->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates));
}

static void parse_remote_parameters(
        int flags,
        void* arg
) {
    struct data_channel_sctp_client* const client = arg;
    enum rawrtc_code error;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    struct rawrtc_ice_parameters* ice_parameters = NULL;
    struct rawrtc_ice_candidates* ice_candidates = NULL;
    struct rawrtc_dtls_parameters* dtls_parameters = NULL;
    struct sctp_parameters sctp_parameters = {0};
    (void) flags;

    // Get dict from JSON
    error = get_json_stdin(&dict);
    if (error) {
        goto out;
    }

    // Decode JSON
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= get_ice_parameters(&ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= get_ice_candidates(&ice_candidates, node, arg);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= get_dtls_parameters(&dtls_parameters, node);
    error |= dict_get_entry(&node, dict, "sctpParameters", ODICT_OBJECT, true);
    error |= get_sctp_parameters(&sctp_parameters, node);

    // Ok?
    if (error) {
        DEBUG_WARNING("Invalid remote parameters\n");
        if (sctp_parameters.capabilities) {
            mem_deref(sctp_parameters.capabilities);
        }
        goto out;
    }

    // Set parameters & start transports
    client->remote_parameters.ice_parameters = mem_ref(ice_parameters);
    client->remote_parameters.ice_candidates = mem_ref(ice_candidates);
    client->remote_parameters.dtls_parameters = mem_ref(dtls_parameters);
    memcpy(&client->remote_parameters.sctp_parameters, &sctp_parameters, sizeof(sctp_parameters));
    DEBUG_INFO("Applying remote parameters\n");
    client_set_parameters(client);
    client_start_transports(client);
    
out:
    // Un-reference
    mem_deref(dtls_parameters);
    mem_deref(ice_candidates);
    mem_deref(ice_parameters);
    mem_deref(dict);
    
    // Exit?
    if (error == RAWRTC_CODE_NO_VALUE) {
        DEBUG_NOTICE("Exiting\n");

        // Stop client & bye
        client_stop(client);
        tmr_cancel(&timer);
        before_exit();
        exit(0);
    }
}

static void client_get_parameters(
        struct data_channel_sctp_client* const client
) {
    struct parameters* const local_parameters = &client->local_parameters;

    // Get local ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, client->gatherer));

    // Get local ICE candidates
    EOE(rawrtc_ice_gatherer_get_local_candidates(
            &local_parameters->ice_candidates, client->gatherer));

    // Get local DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, client->dtls_transport));

    // Get local SCTP parameters
    EOE(rawrtc_sctp_transport_get_capabilities(
            &local_parameters->sctp_parameters.capabilities));
    EOE(rawrtc_sctp_transport_get_port(
            &local_parameters->sctp_parameters.port, client->sctp_transport));
}

static void print_local_parameters(
        struct data_channel_sctp_client *client
) {
    struct odict* dict;
    struct odict* node;

    // Get local parameters
    client_get_parameters(client);

    // Create dict
    EOR(odict_alloc(&dict, 16));

    // Create nodes
    EOR(odict_alloc(&node, 16));
    set_ice_parameters(client->local_parameters.ice_parameters, node);
    EOR(odict_entry_add(dict, "iceParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_ice_candidates(client->local_parameters.ice_candidates, node);
    EOR(odict_entry_add(dict, "iceCandidates", ODICT_ARRAY, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_dtls_parameters(client->local_parameters.dtls_parameters, node);
    EOR(odict_entry_add(dict, "dtlsParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_sctp_parameters(client->sctp_transport, &client->local_parameters.sctp_parameters, node);
    EOR(odict_entry_add(dict, "sctpParameters", ODICT_OBJECT, node));
    mem_deref(node);

    // Print JSON
    DEBUG_INFO("Local Parameters:\n%H\n", json_encode_odict, dict);

    // Un-reference
    mem_deref(dict);
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <0|1 (ice-role)> [<sctp-port>] [<ice-candidate-type> ...]", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
    char* const turn_threema_ch_urls[] = {"turn:turn.threema.ch:443"};
    struct data_channel_sctp_client client = {0};
    (void) client.ice_candidate_types; (void) client.n_ice_candidate_types;

    // Initialise
    EOE(rawrtc_init());

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Check arguments length
    if (argc < 2) {
        exit_with_usage(argv[0]);
    }

    // Get ICE role
    if (get_ice_role(&role, argv[1])) {
        exit_with_usage(argv[0]);
    }

    // Get SCTP port (optional)
    if (argc >= 3 && !str_to_uint16(&client.local_parameters.sctp_parameters.port, argv[2])) {
        exit_with_usage(argv[0]);
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 4) {
        ice_candidate_types = &argv[3];
        n_ice_candidate_types = (size_t) argc - 3;
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

    // Set client fields
    client.name = "A";
    client.ice_candidate_types = ice_candidate_types;
    client.n_ice_candidate_types = n_ice_candidate_types;
    client.gather_options = gather_options;
    client.role = role;

    // Setup client
    client_init(&client);

    // Start gathering
    client_start_gathering(&client);

    // Listen on stdin
    EOR(fd_listen(STDIN_FILENO, FD_READ, parse_remote_parameters, &client));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop client & bye
    client_stop(&client);
    before_exit();
    return 0;
}
