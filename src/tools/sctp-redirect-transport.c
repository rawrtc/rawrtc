#include <stdlib.h> // exit
#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "sctp-redirect-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

// Note: Shadows struct client
struct sctp_redirect_transport_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    char* redirect_ip;
    uint16_t redirect_port;
    enum rawrtc_ice_role role;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_redirect_transport* sctp_redirect_transport;
    struct parameters local_parameters;
    struct parameters remote_parameters;
};

static void print_local_parameters(
    struct sctp_redirect_transport_client *client
);

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct sctp_redirect_transport_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Print local parameters (if last candidate)
    if (!candidate) {
        print_local_parameters(client);
    }
}

static void client_init(
        struct sctp_redirect_transport_client* const client
) {
    struct rawrtc_certificate* certificates[1];

    // Generate certificates
    EOE(rawrtc_certificate_generate(&client->certificate, NULL));
    certificates[0] = client->certificate;

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &client->gatherer, client->gather_options,
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
            default_dtls_transport_state_change_handler, default_dtls_transport_error_handler,
            client));

    // Create SCTP redirect transport
    EOE(rawrtc_sctp_redirect_transport_create(
            &client->sctp_redirect_transport, client->dtls_transport,
            0, client->redirect_ip, client->redirect_port));
}

static void client_start_gathering(
        struct sctp_redirect_transport_client* const client
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(client->gatherer, NULL));
}

static void client_set_parameters(
        struct sctp_redirect_transport_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Set remote ICE candidates
    EOE(rawrtc_ice_transport_set_remote_candidates(
            client->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates));
}

static void client_start_transports(
        struct sctp_redirect_transport_client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters,
            client->role));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters));

    // Start SCTP redirect transport
    EOE(rawrtc_sctp_redirect_transport_start(
            client->sctp_redirect_transport, remote_parameters->sctp_parameters.capabilities,
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
        struct sctp_redirect_transport_client* const client
) {
    if (client->sctp_redirect_transport) {
        EOE(rawrtc_sctp_redirect_transport_stop(client->sctp_redirect_transport));
    }
    if (client->dtls_transport) {
        EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    }
    if (client->ice_transport) {
        EOE(rawrtc_ice_transport_stop(client->ice_transport));
    }
    if (client->gatherer) {
        EOE(rawrtc_ice_gatherer_close(client->gatherer));
    }

    // Un-reference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->sctp_redirect_transport = mem_deref(client->sctp_redirect_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);
}

static void parse_remote_parameters(
        int flags,
        void* arg
) {
    struct sctp_redirect_transport_client* const client = arg;
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
        re_cancel();
    }
}

static void client_get_parameters(
        struct sctp_redirect_transport_client* const client
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

    // Get redirected local SCTP port
    EOE(rawrtc_sctp_redirect_transport_get_port(
            &local_parameters->sctp_parameters.port, client->sctp_redirect_transport));
}

static void print_local_parameters(
        struct sctp_redirect_transport_client *client
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
    set_sctp_redirect_parameters(
            client->sctp_redirect_transport, &client->local_parameters.sctp_parameters, node);
    EOR(odict_entry_add(dict, "sctpParameters", ODICT_OBJECT, node));
    mem_deref(node);

    // Print JSON
    DEBUG_INFO("Local Parameters:\n%H\n", json_encode_odict, dict);

    // Un-reference
    mem_deref(dict);
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <0|1 (ice-role)> <redirect-ip> <redirect-port> [<sctp-port>] "
                  "[<maximum-message-size>] [<ice-candidate-type> ...]", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    uint16_t redirect_port;
    uint64_t maximum_message_size;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun:stun.l.google.com:19302",
                                          "stun:stun1.l.google.com:19302"};
    char* const turn_threema_ch_urls[] = {"turn:turn.threema.ch:443"};
    struct sctp_redirect_transport_client client = {0};
    (void) client.ice_candidate_types; (void) client.n_ice_candidate_types;

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Initialise
    EOE(rawrtc_init(true));

    // Check arguments length
    if (argc < 4) {
        exit_with_usage(argv[0]);
    }

    // Get ICE role
    if (get_ice_role(&role, argv[1])) {
        exit_with_usage(argv[0]);
    }

    // Get redirect port
    if (!str_to_uint16(&redirect_port, argv[3])) {
        exit_with_usage(argv[0]);
    }

    // Get SCTP port (optional)
    if (argc >= 5 && !str_to_uint16(&client.local_parameters.sctp_parameters.port, argv[4])) {
        exit_with_usage(argv[0]);
    }

    // Get maximum message size (optional)
    if (argc >= 6 && !str_to_uint64(&maximum_message_size, argv[5])) {
        exit_with_usage(argv[0]);
    } else {
        // TODO: Find out what dctt can handle
        maximum_message_size = 0;
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 7) {
        ice_candidate_types = &argv[6];
        n_ice_candidate_types = (size_t) argc - 6;
    }

    // Create local SCTP capabilities
    rawrtc_sctp_capabilities_create(
            &client.local_parameters.sctp_parameters.capabilities, maximum_message_size);

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
    client.redirect_ip = argv[2];
    client.redirect_port = redirect_port;

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
