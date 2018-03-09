#include <stdlib.h> // exit
#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "data-channel-sctp-throughput-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
    struct sctp_parameters sctp_parameters;
};

// Note: Shadows struct client
struct data_channel_sctp_throughput_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    uint64_t message_size;
    uint16_t n_times_left;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    struct mbuf* start_buffer;
    struct mbuf* throughput_buffer;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct data_channel_helper* data_channel;
    struct parameters local_parameters;
    struct parameters remote_parameters;
    uint64_t start_time;
};

static void print_local_parameters(
    struct data_channel_sctp_throughput_client *client
);

static struct tmr timer = {{0}};

static void timer_handler(
        void* arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_throughput_client* const client =
            (struct data_channel_sctp_throughput_client*) channel->client;
    enum rawrtc_code error;
    enum rawrtc_dtls_role role;

    // Send start indicator
    mbuf_set_pos(client->start_buffer, 0);
    DEBUG_PRINTF("(%s) Sending start indicator\n", client->name);
    error = rawrtc_data_channel_send(channel->channel, client->start_buffer, false);
    if (error) {
        DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
        goto out;
    }

    // Send message
    DEBUG_PRINTF("(%s) Sending %zu bytes\n",
                 client->name, mbuf_get_left(client->throughput_buffer));
    error = rawrtc_data_channel_send(channel->channel, client->throughput_buffer, true);
    if (error) {
        DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
        goto out;
    }

out:
    // Get DTLS role
    EOE(rawrtc_dtls_parameters_get_role(&role, client->local_parameters.dtls_parameters));
    if (role == RAWRTC_DTLS_ROLE_CLIENT) {
        // Close bear-noises
        DEBUG_PRINTF("(%s) Closing channel\n", client->name, channel->label);
        EOR(rawrtc_data_channel_close(client->data_channel->channel));
    }
}

static void data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg
) {
    struct data_channel_helper* const channel = arg;
    struct data_channel_sctp_throughput_client* const client =
            (struct data_channel_sctp_throughput_client*) channel->client;
    size_t const length = mbuf_get_left(buffer);

    // Check role
    if (client->role != RAWRTC_ICE_ROLE_CONTROLLED) {
        DEBUG_WARNING("(%s) Unexpected message on data channel %s of size %zu\n",
                      client->name, channel->label, length);
    }

    if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_STRING) {
        // Start indicator message
        uint64_t expected_size;

        // Check size
        if (mbuf_get_left(buffer) < 8) {
            EOE(RAWRTC_CODE_INVALID_MESSAGE);
        }

        // Parse message
        expected_size = sys_ntohll(mbuf_read_u64(buffer));
        EOE(expected_size > 0 ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_INVALID_MESSAGE);
        client->start_time = tmr_jiffies();
        DEBUG_INFO("(%s) Started throughput test of %.2f MiB\n",
                   client->name, ((double) expected_size) / 1048576);
        return;
    } else if (flags & RAWRTC_DATA_CHANNEL_MESSAGE_FLAG_IS_BINARY) {
        // Check expected message size and print results
        double const delta = ((double) (tmr_jiffies() - client->start_time)) / 1000;
        DEBUG_INFO("(%s) Completed throughput test after %.2f seconds: %.2f Mbit/s\n",
                   client->name, delta, ((double) length) / 131072 / delta);

        // Check size
        if (length != client->message_size) {
            DEBUG_WARNING("(%s) Expected %zu bytes, received %zu bytes\n", client->name,
                          client->message_size, length);
            return;
        }
    }
}

static void start_throughput_test(
        struct data_channel_helper* const channel
) {
    struct data_channel_sctp_throughput_client* const client =
            (struct data_channel_sctp_throughput_client*) channel->client;

    // Start throughput test delayed (if controlling)
    if (client->role == RAWRTC_ICE_ROLE_CONTROLLING && client->n_times_left > 0) {
        mbuf_set_pos(client->throughput_buffer, 0);
        DEBUG_INFO("Starting throughput test of %.2f MiB in 1 second\n",
                   ((double) mbuf_get_left(client->throughput_buffer)) / 1048576);
        tmr_start(&timer, 1000, timer_handler, channel);
        --client->n_times_left;
    }
}

static void data_channel_buffered_amount_low_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;

    // Print buffered amount low event
    default_data_channel_buffered_amount_low_handler(arg);

    // Restart throughput test
    start_throughput_test(channel);
}

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;

    // Print open event
    default_data_channel_open_handler(arg);

    // Start throughput test
    start_throughput_test(channel);
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct data_channel_sctp_throughput_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Print local parameters (if last candidate)
    if (!candidate) {
        print_local_parameters(client);
    }
}

static void client_init(
        struct data_channel_sctp_throughput_client* const client
) {
    struct rawrtc_certificate* certificates[1];
    struct rawrtc_data_channel_parameters* channel_parameters;

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
            &client->data_channel, (struct client *) client, "throughput");

    // Create data channel parameters
    EOE(rawrtc_data_channel_parameters_create(
            &channel_parameters, client->data_channel->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0));

    // Create pre-negotiated data channel
    EOE(rawrtc_data_channel_create(
            &client->data_channel->channel, client->data_transport, channel_parameters,
            data_channel_open_handler, data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            data_channel_message_handler, client->data_channel));

    // Un-reference
    mem_deref(channel_parameters);
}

static void client_start_gathering(
        struct data_channel_sctp_throughput_client* const client
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(client->gatherer, NULL));
}

static void client_start_transports(
        struct data_channel_sctp_throughput_client* const client
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
        struct data_channel_sctp_throughput_client* const client
) {
    if (client->sctp_transport) {
        EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
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
    client->data_channel = mem_deref(client->data_channel);
    client->data_transport = mem_deref(client->data_transport);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->throughput_buffer = mem_deref(client->throughput_buffer);
    client->start_buffer = mem_deref(client->start_buffer);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);
}

static void client_set_parameters(
        struct data_channel_sctp_throughput_client* const client
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
    struct data_channel_sctp_throughput_client* const client = arg;
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
        re_cancel();
    }
}

static void client_get_parameters(
        struct data_channel_sctp_throughput_client* const client
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
        struct data_channel_sctp_throughput_client *client
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
    DEBUG_WARNING("Usage: %s <0|1 (ice-role)> <message-size> [<n-times>] [<sctp-port>] "
                          "[<ice-candidate-type> ...]", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    struct rawrtc_ice_gather_options* gather_options;
    struct data_channel_sctp_throughput_client client = {0};
    (void) client.ice_candidate_types; (void) client.n_ice_candidate_types;

    // Debug
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Initialise
    EOE(rawrtc_init(true));

    // Check arguments length
    if (argc < 3) {
        exit_with_usage(argv[0]);
    }

    // Get ICE role
    if (get_ice_role(&role, argv[1])) {
        exit_with_usage(argv[0]);
    }

    // Get message size
    if (!str_to_uint64(&client.message_size, argv[2])) {
        exit_with_usage(argv[0]);
    }

    // Get number of times the test should run (optional)
    client.n_times_left = 1;
    if (argc >= 4 && !str_to_uint16(&client.n_times_left, argv[3])) {
        exit_with_usage(argv[0]);
    }

    // TODO: Add possibility to turn checksum generation/validation on or off

    // Get SCTP port (optional)
    if (argc >= 5 && !str_to_uint16(&client.local_parameters.sctp_parameters.port, argv[4])) {
        exit_with_usage(argv[0]);
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 6) {
        ice_candidate_types = &argv[5];
        n_ice_candidate_types = (size_t) argc - 5;
    }

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_POLICY_ALL));

    // Set client fields
    client.name = "A";
    client.ice_candidate_types = ice_candidate_types;
    client.n_ice_candidate_types = n_ice_candidate_types;
    client.gather_options = gather_options;
    client.role = role;

    // Pre-generate messages (if 'controlling')
    if (role == RAWRTC_ICE_ROLE_CONTROLLING) {
        // Start indicator
        client.start_buffer = mbuf_alloc(8);
        EOE(client.start_buffer ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_NO_MEMORY);
        EOR(mbuf_write_u64(client.start_buffer, sys_htonll(client.message_size)));

        // Throughput test buffer
        client.throughput_buffer = mbuf_alloc(client.message_size);
        EOE(client.throughput_buffer ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_NO_MEMORY);
        EOR(mbuf_fill(client.throughput_buffer, 0x01, mbuf_get_space(client.throughput_buffer)));
    }

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
