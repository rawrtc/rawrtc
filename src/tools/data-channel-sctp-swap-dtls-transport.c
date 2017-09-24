#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "data-channel-sctp-swap-dtls-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

// Note: Shadows struct client
struct ice_dtls {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct le le;
    uint32_t index;
    bool parameters_set;
    struct data_channel_sctp_swap_dtls_transport_client* client;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
};

// Note: Shadows struct client
struct data_channel_sctp_swap_dtls_transport_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    uint16_t sctp_port;
    struct list ice_dtls_list;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct data_channel_helper* data_channel_negotiated;
    struct data_channel_helper* data_channel;
};

static void print_local_parameters(
    struct ice_dtls* const ice_dtls
);

static struct tmr timer = {{0}};

static void timer_handler(
        void* arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_swap_dtls_transport_client* const client =
            (struct data_channel_sctp_swap_dtls_transport_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_dtls_parameters* dtls_parameters;
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

    // Get DTLS transport
    EOE(rawrtc_sctp_transport_get_transport(&dtls_transport, client->sctp_transport));

    // Get DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(&dtls_parameters, dtls_transport));

    // Get DTLS role
    EOE(rawrtc_dtls_parameters_get_role(&role, dtls_parameters));
    if (role == RAWRTC_DTLS_ROLE_CLIENT) {
        // Close bear-noises
        DEBUG_PRINTF("(%s) Closing channel\n", client->name, channel->label);
        EOR(rawrtc_data_channel_close(client->data_channel->channel));
    }

    // Un-reference
    mem_deref(dtls_parameters);
    mem_deref(dtls_transport);
}

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_swap_dtls_transport_client* const client =
            (struct data_channel_sctp_swap_dtls_transport_client*) channel->client;
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
    struct ice_dtls* const ice_dtls = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Print local parameters (if last candidate)
    if (!candidate) {
        print_local_parameters(ice_dtls);
    }
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct ice_dtls* const ice_dtls = arg;
    struct data_channel_sctp_swap_dtls_transport_client* const client = ice_dtls->client;

    // Print state
    default_dtls_transport_state_change_handler(state, arg);

    // Connected?
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        if (ice_dtls->index == 0) {
            // Open? Create new data channel
            // TODO: Move this once we can create data channels earlier
            struct rawrtc_dtls_parameters* dtls_parameters;
            enum rawrtc_dtls_role role;

            // Get DTLS parameters
            EOE(rawrtc_dtls_transport_get_local_parameters(
                    &dtls_parameters, ice_dtls->dtls_transport));

            // Get DTLS role
            EOE(rawrtc_dtls_parameters_get_role(&role, dtls_parameters));
            mem_deref(dtls_parameters);
            DEBUG_PRINTF("(%s) DTLS role: %s\n", ice_dtls->name, rawrtc_dtls_role_to_str(role));

            // Client? Create data channel
            if (role == RAWRTC_DTLS_ROLE_CLIENT) {
                struct rawrtc_data_channel_parameters *channel_parameters;

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
        } else {
            // Swap DTLS transport on the SCTP transport
            EOE(rawrtc_sctp_transport_set_transport(
                    client->sctp_transport, ice_dtls->dtls_transport));
            DEBUG_INFO("Switched SCTP transport to DTLS transport #%"PRIu32"\n",
                       ice_dtls->index + 1);
        }
    }
}

static void ice_dtls_destroy(
        void* arg
) {
    struct ice_dtls* const ice_dtls = arg;

    // Un-reference
    mem_deref(ice_dtls->dtls_transport);
    mem_deref(ice_dtls->ice_transport);
    mem_deref(ice_dtls->gatherer);
    mem_deref(ice_dtls->certificate);
    mem_deref(ice_dtls->name);
}

static void ice_dtls_add(
        struct ice_dtls** const ice_dtlsp, // de-referenced
        struct data_channel_sctp_swap_dtls_transport_client* const client
) {
    struct ice_dtls* ice_dtls;
    uint32_t const index = list_count(&client->ice_dtls_list);
    struct rawrtc_certificate* certificates[1];

    // Allocate
    ice_dtls = mem_zalloc(sizeof(*ice_dtls), ice_dtls_destroy);
    if (!ice_dtls) {
        EOE(RAWRTC_CODE_NO_MEMORY);
    }

    // Set fields
    EOE(rawrtc_sdprintf(&ice_dtls->name, "%s (#%"PRIu32")", client->name, index + 1));
    ice_dtls->ice_candidate_types = client->ice_candidate_types;
    ice_dtls->n_ice_candidate_types = client->n_ice_candidate_types;
    (void) ice_dtls->ice_candidate_types; (void) ice_dtls->n_ice_candidate_types;
    ice_dtls->index = index;
    ice_dtls->parameters_set = false;
    ice_dtls->client = client;

    // Generate certificate
    EOE(rawrtc_certificate_generate(&ice_dtls->certificate, NULL));
    certificates[0] = ice_dtls->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &ice_dtls->gatherer, client->gather_options,
            default_ice_gatherer_state_change_handler, default_ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, ice_dtls));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &ice_dtls->ice_transport, ice_dtls->gatherer,
            default_ice_transport_state_change_handler,
            default_ice_transport_candidate_pair_change_handler, ice_dtls));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &ice_dtls->dtls_transport, ice_dtls->ice_transport, certificates,
            ARRAY_SIZE(certificates), dtls_transport_state_change_handler,
            default_dtls_transport_error_handler, ice_dtls));

    // Add to list and set pointer
    list_append(&client->ice_dtls_list, &ice_dtls->le, ice_dtls);
    if (ice_dtlsp) {
        *ice_dtlsp = mem_ref(ice_dtls);
    }
    DEBUG_INFO("Added new ICE gatherer, ICE transport, DTLS transport (#%"PRIu32")\n",
               list_count(&client->ice_dtls_list));
}

static void client_init(
        struct data_channel_sctp_swap_dtls_transport_client* const client
) {
    struct ice_dtls* ice_dtls;
    struct rawrtc_data_channel_parameters* channel_parameters;

    // Create ICE gatherer, ICE transport, DTLS transport
    ice_dtls_add(&ice_dtls, client);

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &client->sctp_transport, ice_dtls->dtls_transport, client->sctp_port,
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
    mem_deref(ice_dtls);
}

static void client_start_gathering(
        struct ice_dtls* const ice_dtls
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(ice_dtls->gatherer, NULL));
}

static void client_start_transports(
        struct ice_dtls* const ice_dtls,
        struct parameters* const remote_parameters
) {
    struct data_channel_sctp_swap_dtls_transport_client* const client = ice_dtls->client;

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            ice_dtls->ice_transport, ice_dtls->gatherer, remote_parameters->ice_parameters,
            client->role));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            ice_dtls->dtls_transport, remote_parameters->dtls_parameters));

    // Start SCTP transport (if initial DTLS transport)
    if (ice_dtls->index == 0) {
        EOE(rawrtc_sctp_transport_start(
                client->sctp_transport, remote_parameters->sctp_parameters.capabilities,
                remote_parameters->sctp_parameters.port));
    }
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

static void ice_dtls_stop(
        struct ice_dtls* const ice_dtls
) {
    EOE(rawrtc_dtls_transport_stop(ice_dtls->dtls_transport));
    EOE(rawrtc_ice_transport_stop(ice_dtls->ice_transport));
    EOE(rawrtc_ice_gatherer_close(ice_dtls->gatherer));
}

static void client_stop(
        struct data_channel_sctp_swap_dtls_transport_client* const client
) {
    struct le* le;

    // Stop SCTP transport
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));

    // Stop all ICE gatherer, ICE transports and DTLS transports
    for (le = list_head(&client->ice_dtls_list); le != NULL; le = le->next) {
        struct ice_dtls* const ice_dtls = le->data;
        ice_dtls_stop(ice_dtls);
    }

    // Un-reference & close
    client->data_channel = mem_deref(client->data_channel);
    client->data_channel_negotiated = mem_deref(client->data_channel_negotiated);
    client->data_transport = mem_deref(client->data_transport);
    client->sctp_transport = mem_deref(client->sctp_transport);
    list_flush(&client->ice_dtls_list);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);
}

static void client_set_parameters(
        struct ice_dtls* const ice_dtls,
        struct parameters* const remote_parameters
) {
    // Set remote ICE candidates
    EOE(rawrtc_ice_transport_set_remote_candidates(
            ice_dtls->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates));
}

static void stdin_handler(
        int flags,
        void *arg
) {
    struct data_channel_sctp_swap_dtls_transport_client* const client = arg;
    char buffer[PARAMETERS_MAX_LENGTH];
    size_t length;
    // Note: At this point there's at least one instance.
    struct ice_dtls* const ice_dtls =
            (struct ice_dtls* const) list_tail(&client->ice_dtls_list)->data;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    struct parameters remote_parameters = {0};
    (void) flags;

    // Get data from stdin
    if (!fgets((char*) buffer, ARRAY_SIZE(buffer), stdin)) {
        EWE("Error polling stdin");
    }
    length = strlen(buffer);

    // Add DTLS transport?
    if (length > 0 && buffer[0] == '+') {
        struct ice_dtls* ice_dtls_new;

        // Add new ICE gatherer, ICE transport, DTLS transport
        ice_dtls_add(&ice_dtls_new, client);

        // Start gathering
        client_start_gathering(ice_dtls_new);

        // Un-reference & out
        mem_deref(ice_dtls_new);
        goto out;
    }

    // Get dict from JSON
    error = get_json(&dict, buffer, length);
    if (error) {
        goto out;
    }

    // Check if setting parameters is required
    if (ice_dtls->parameters_set) {
        DEBUG_WARNING("ICE parameters on #%"PRIu32" already set\n", ice_dtls->index + 1);
        goto out;
    }

    // Decode JSON
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= get_ice_parameters(&remote_parameters.ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= get_ice_candidates(&remote_parameters.ice_candidates, node, arg);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= get_dtls_parameters(&remote_parameters.dtls_parameters, node);
    if (error) {
        goto out;
    }
    switch (dict_get_entry(&node, dict, "sctpParameters", ODICT_OBJECT, false)) {
        case RAWRTC_CODE_SUCCESS:
            error = get_sctp_parameters(&remote_parameters.sctp_parameters, node);
            break;
        case RAWRTC_CODE_NO_VALUE:
            error = RAWRTC_CODE_SUCCESS;
            break;
        default:
            // Parameters handled (if any)
            break;
    }

    // Ok?
    if (error) {
        goto out;
    }

    // Set parameters & start transports
    DEBUG_INFO("Applying remote parameters\n");
    client_set_parameters(ice_dtls, &remote_parameters);
    client_start_transports(ice_dtls, &remote_parameters);
    ice_dtls->parameters_set = true;
    
out:
    // Un-reference
    mem_deref(dict);
    parameters_destroy(&remote_parameters);

    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            break;
        case RAWRTC_CODE_NO_VALUE:
            // Exit
            DEBUG_NOTICE("Exiting\n");

            // Stop client & bye
            client_stop(client);
            tmr_cancel(&timer);
            before_exit();
            exit(0);
            break;
        default:
            DEBUG_WARNING("Invalid remote parameters, try again!\n");
            break;
    }
}

static void client_get_parameters(
        struct parameters* const local_parameters,
        struct ice_dtls* const ice_dtls
) {
    struct data_channel_sctp_swap_dtls_transport_client* const client = ice_dtls->client;

    // Get local ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, ice_dtls->gatherer));

    // Get local ICE candidates
    EOE(rawrtc_ice_gatherer_get_local_candidates(
            &local_parameters->ice_candidates, ice_dtls->gatherer));

    // Get local DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, ice_dtls->dtls_transport));

    // Get local SCTP parameters (if initial DTLS transport)
    if (ice_dtls->index == 0) {
        EOE(rawrtc_sctp_transport_get_capabilities(
                &local_parameters->sctp_parameters.capabilities));
        EOE(rawrtc_sctp_transport_get_port(
                &local_parameters->sctp_parameters.port, client->sctp_transport));
    }
}

static void print_local_parameters(
        struct ice_dtls* const ice_dtls
) {
    struct data_channel_sctp_swap_dtls_transport_client* const client = ice_dtls->client;
    struct parameters local_parameters = {0};
    struct odict* dict;
    struct odict* node;

    // Get local parameters
    client_get_parameters(&local_parameters, ice_dtls);

    // Create dict
    EOR(odict_alloc(&dict, 16));

    // Create nodes
    EOR(odict_alloc(&node, 16));
    set_ice_parameters(local_parameters.ice_parameters, node);
    EOR(odict_entry_add(dict, "iceParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_ice_candidates(local_parameters.ice_candidates, node);
    EOR(odict_entry_add(dict, "iceCandidates", ODICT_ARRAY, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    set_dtls_parameters(local_parameters.dtls_parameters, node);
    EOR(odict_entry_add(dict, "dtlsParameters", ODICT_OBJECT, node));
    mem_deref(node);
    if (ice_dtls->index == 0) {
        EOR(odict_alloc(&node, 16));
        set_sctp_parameters(client->sctp_transport, &local_parameters.sctp_parameters, node);
        EOR(odict_entry_add(dict, "sctpParameters", ODICT_OBJECT, node));
        mem_deref(node);
    }

    // Print JSON
    DEBUG_INFO("Local Parameters:\n%H\n", json_encode_odict, dict);

    // Un-reference
    mem_deref(dict);
    parameters_destroy(&local_parameters);
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
    struct data_channel_sctp_swap_dtls_transport_client client = {0};
    struct ice_dtls* ice_dtls;
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
    if (argc >= 3 && !str_to_uint16(&client.sctp_port, argv[2])) {
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
            gather_options, stun_google_com_urls, ARRAY_SIZE(stun_google_com_urls),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_TYPE_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_threema_ch_urls, ARRAY_SIZE(turn_threema_ch_urls),
            "threema-angular", "Uv0LcCq3kyx6EiRwQW5jVigkhzbp70CjN2CJqzmRxG3UGIdJHSJV6tpo7Gj7YnGB",
            RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD));

    // Set client fields
    client.name = "A";
    client.ice_candidate_types = ice_candidate_types;
    client.n_ice_candidate_types = n_ice_candidate_types;
    client.gather_options = gather_options;
    client.role = role;
    list_init(&client.ice_dtls_list);

    // Setup client
    client_init(&client);

    // Start gathering
    ice_dtls = (struct ice_dtls* const) list_head(&client.ice_dtls_list)->data;
    client_start_gathering(ice_dtls);

    // Listen on stdin
    EOR(fd_listen(STDIN_FILENO, FD_READ, stdin_handler, &client));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop client & bye
    client_stop(&client);
    before_exit();
    return 0;
}
