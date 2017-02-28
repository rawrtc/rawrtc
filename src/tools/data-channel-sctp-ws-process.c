#include <string.h> // memcpy
#include <unistd.h> // STDIN_FILENO, STDOUT_FILENO, pipe, fork, dup2, close, execvp, read, write
#include <signal.h> // SIGTERM, kill
#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"
#include "helper/parameters.h"

#define DEBUG_MODULE "data-channel-sctp-echo-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

enum {
    PIPE_READ_BUFFER = 4096
};

char const NL[] = "\n";

struct pipe {
    int read;
    int write;
};

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
    char* ws_url;
    struct rawrtc_ice_gather_options* gather_options;
    enum rawrtc_ice_role role;
    struct dnsc* dns_client;
    struct http_cli* http_client;
    struct websock* ws_socket;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_sctp_transport* sctp_transport;
    struct rawrtc_data_transport* data_transport;
    struct websock_conn* ws_connection;
    struct list data_channels;
    struct parameters local_parameters;
    struct parameters remote_parameters;
};

// Note: Shwadows struct data_channel_helper
struct data_channel_sctp_client_data_channel_helper {
    struct rawrtc_data_channel* channel;
    char* label;
    struct client* client;
    struct le le;
    pid_t pid;
    struct pipe pipe;
};

static void client_start_transports(
    struct data_channel_sctp_client* const client
);

static void client_set_parameters(
    struct data_channel_sctp_client* const client
);

static void client_get_parameters(
    struct data_channel_sctp_client* const client
);

/*
 * Print the WS close event.
 */
static void ws_close_handler(
        int err,
        void* arg
) {
    struct data_channel_sctp_client* const client = arg;
    DEBUG_PRINTF("(%s) WS connection closed, reason: %m\n", client->name, err);
}

/*
 * Parse the JSON encoded remote parameters and apply them.
 */
static void ws_receive_handler(
        struct websock_hdr const* header,
        struct mbuf* buffer,
        void* arg
) {
    struct data_channel_sctp_client* const client = arg;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct rawrtc_ice_parameters* ice_parameters = NULL;
    struct rawrtc_ice_candidates* ice_candidates = NULL;
    struct rawrtc_dtls_parameters* dtls_parameters = NULL;
    struct sctp_parameters sctp_parameters = {0};
    (void) header;
    DEBUG_PRINTF("(%s) WS message of %zu bytes received\n", client->name, mbuf_get_left(buffer));

    // Check opcode
    if (header->opcode != WEBSOCK_TEXT) {
        DEBUG_NOTICE("(%s) Unexpected opcode (%u) in WS message\n", client->name, header->opcode);
        return;
    }

    // Decode JSON
    EOR(json_decode_odict(&dict, 16, (char*) mbuf_buf(buffer), mbuf_get_left(buffer), 3));

    // Decode content
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
        DEBUG_WARNING("(%s) Invalid remote parameters\n", client->name);
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
    DEBUG_INFO("(%s) Applying remote parameters\n", client->name);
    client_set_parameters(client);
    client_start_transports(client);

out:
    // Close WS connection
    EOR(websock_close(client->ws_connection, WEBSOCK_GOING_AWAY, "Cya!"));

    // Dereference
    mem_deref(dtls_parameters);
    mem_deref(ice_candidates);
    mem_deref(ice_parameters);
    mem_deref(dict);
}

/*
 * Send the JSON encoded local parameters to the other peer.
 */
static void ws_established_handler(
        void* arg
) {
    struct data_channel_sctp_client* const client = arg;
    struct odict* dict;
    struct odict* node;
    DEBUG_PRINTF("(%s) WS connection established\n", client->name);

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

    // Send JSON
    DEBUG_INFO("(%s) Sending local parameters\n", client->name);
    EOR(websock_send(client->ws_connection, WEBSOCK_TEXT, "%H", json_encode_odict, dict));

    // Dereference
    mem_deref(dict);
}

/*
 * Print the local candidate. Open a connection to the WS server in
 * case all candidates have been gathered.
 */
static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct data_channel_sctp_client* const client = arg;

    // Print local candidate
    default_ice_gatherer_local_candidate_handler(candidate, url, arg);

    // Connect to WS server (if last candidate)
    if (!candidate) {
        EOR(websock_connect(
                &client->ws_connection, client->ws_socket, client->http_client,
                client->ws_url, 30000,
                ws_established_handler, ws_receive_handler, ws_close_handler,
                client, NULL));
    }
}

/*
 * Print the data channel's received message's size and echo the
 * message back.
 */
void data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_sctp_client_data_channel_helper* const channel = arg;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client* const) channel->client;
    size_t const length = mbuf_get_left(buffer);
    (void) flags;
    DEBUG_PRINTF("(%s.%s) Received %zu bytes\n", client->name, channel->label, length);

    // Pipe into forked process's stdin
    // TODO: Blocking? EAGAIN?
    DEBUG_PRINTF("(%s.%s) Piping %zu bytes into process...\n",
                 client->name, channel->label, length);
    EOP(write(channel->pipe.write, mbuf_buf(buffer), length));
    EOP(write(channel->pipe.write, NL, sizeof(NL)));
    DEBUG_PRINTF("(%s.%s) ... completed!\n", client->name, channel->label);
}

/*
 * Stop the forked process.
 */
static void stop_process(
        struct data_channel_sctp_client_data_channel_helper* const channel
) {
    // Close read pipe (if not already closed)
    if (channel->pipe.read != -1) {
        // Stop listening on pipe
        fd_close(channel->pipe.read);
        EOP(close(channel->pipe.read));

        // Invalidate pipe
        channel->pipe.read = -1;
    }

    // Close write pipe (if not already closed)
    if (channel->pipe.write != -1) {
        // Stop listening on pipe
        EOP(close(channel->pipe.write));

        // Invalidate pipe
        channel->pipe.write = -1;
    }

    // Stop process (if not already stopped)
    if (channel->pid != -1) {
        DEBUG_INFO("(%s.%s) Stopping process\n", channel->client->name, channel->label);

        // Terminate process
        EOP(kill(channel->pid, SIGTERM));

        // Invalidate process
        channel->pid = -1;
    }
}

/*
 * Stop the forked process on error event.
 */
static void data_channel_error_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_sctp_client_data_channel_helper* const channel = arg;

    // Print error event
    default_data_channel_error_handler(arg);

    // Stop forked process
    stop_process(channel);
}

/*
 * Stop the forked process on close event.
 */
void data_channel_close_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_sctp_client_data_channel_helper* const channel = arg;

    // Print close event
    default_data_channel_close_handler(arg);

    // Stop forked process
    stop_process(channel);
}

/*
 * Send the forked processes's stdout data on the data channel.
 */
static void pipe_read_handler(
        int flags,
        void* arg
) {
    struct data_channel_sctp_client_data_channel_helper* const channel = arg;
    struct data_channel_sctp_client* const client =
            (struct data_channel_sctp_client* const) channel->client;
    ssize_t length;
    (void) flags;

    // Create buffer
    struct mbuf* const buffer = mbuf_alloc(PIPE_READ_BUFFER);

    // Read from pipe into buffer
    // TODO: Blocking? EAGAIN?
    DEBUG_PRINTF("(%s.%s) Reading from process...\n", client->name, channel->label);
    length = read(channel->pipe.read, mbuf_buf(buffer), mbuf_get_space(buffer));
    EOP(length);
    mbuf_set_end(buffer, (size_t) length);
    DEBUG_PRINTF("(%s.%s) ... read %zu bytes\n",
                 client->name, channel->label, mbuf_get_left(buffer));

    // Process terminated?
    if (length == 0) {
        // Stop listening
        stop_process(channel);

        // Close data channel
        EOE(rawrtc_data_channel_close(channel->channel));

        // Unreference helper
        mem_deref(channel);
    } else {
        // Send the buffer
        DEBUG_PRINTF("(%s.%s) Sending %zu bytes\n", client->name, channel->label, length);
        EOE(rawrtc_data_channel_send(channel->channel, buffer, false));
    }

    // Clean up
    mem_deref(buffer);
}

/*
 * Fork and start the process on open event.
 */
static void data_channel_open_handler(
        void* const arg // will be casted to `struct data_channel_helper*`
) {
    struct data_channel_sctp_client_data_channel_helper* const channel = arg;
    pid_t pid;
    int parent_write_pipe[2];
    int parent_read_pipe[2];

    // Print open event
    default_data_channel_open_handler(arg);

    // Create pipes (where 0 is read and 1 is write)
    EOP(pipe(parent_write_pipe));
    EOP(pipe(parent_read_pipe));

    // Fork process
    // TODO: Fix leaking FDs
    pid = fork();
    EOP(pid);

    // Child process
    if (pid == 0) {
        // TODO: Get child arguments and file from parent arguments
        char* const args[] = {"bash", NULL};

        // Map stdin to read end of the parent's write pipe
        EOP(dup2(parent_write_pipe[0], STDIN_FILENO));

        // Map stdout to write end of the parent's read pipe
        EOP(dup2(parent_read_pipe[1], STDOUT_FILENO));

        // Close inherited pipes
        EOP(close(parent_write_pipe[0]));
        EOP(close(parent_write_pipe[1]));
        EOP(close(parent_read_pipe[0]));
        EOP(close(parent_read_pipe[1]));

        // Run process
        DEBUG_INFO("(%s) Starting process for data channel %s\n",
                   channel->client->name, channel->label);
        EOP(execvp(args[0], args));
        EWE("Child process returned!\n");
    }

    // Close pipe ends used by the child
    EOP(close(parent_write_pipe[0]));
    EOP(close(parent_read_pipe[1]));

    // Set fields
    channel->pid = pid;
    channel->pipe.read = parent_read_pipe[0];
    channel->pipe.write = parent_write_pipe[1];

    // Listen on pipe
    EOR(fd_listen(channel->pipe.read, FD_READ, pipe_read_handler, channel));
}

/*
 * Handle the newly created data channel.
 */
static void data_channel_handler(
        struct rawrtc_data_channel* const channel, // read-only, MUST be referenced when used
        void* const arg // will be casted to `struct client*`
) {
    struct data_channel_sctp_client* const client = arg;
    struct data_channel_sctp_client_data_channel_helper* channel_helper;

    // Print channel
    default_data_channel_handler(channel, arg);

    // Create data channel helper instance
    // Note: In this case we need to reference the channel because we have not created it
    data_channel_helper_create_from_channel(
            (struct data_channel_helper**) &channel_helper, sizeof(*channel_helper),
            mem_ref(channel), arg);

    // Set PID to invalid
    channel_helper->pid = -1;

    // Add to list
    list_append(&client->data_channels, &channel_helper->le, channel_helper);

    // Set handler argument & handlers
    EOE(rawrtc_data_channel_set_arg(channel, channel_helper));
    EOE(rawrtc_data_channel_set_open_handler(channel, data_channel_open_handler));
    EOE(rawrtc_data_channel_set_buffered_amount_low_handler(
            channel, default_data_channel_buffered_amount_low_handler));
    EOE(rawrtc_data_channel_set_error_handler(channel, data_channel_error_handler));
    EOE(rawrtc_data_channel_set_close_handler(channel, data_channel_close_handler));
    EOE(rawrtc_data_channel_set_message_handler(channel, data_channel_message_handler));
}

static void client_init(
        struct data_channel_sctp_client* const client
) {
    struct rawrtc_certificate* certificates[1];

    // Create DNS client
    EOR(dnsc_alloc(&client->dns_client, NULL, NULL, 0));

    // Create HTTP client
    EOR(http_client_alloc(&client->http_client, client->dns_client));

    // Create WS Socket
    EOR(websock_alloc(&client->ws_socket, NULL, client));

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
            &client->dtls_transport, client->ice_transport, certificates,
            sizeof(certificates) / sizeof(certificates[0]),
            default_dtls_transport_state_change_handler, default_dtls_transport_error_handler,
            client));

    // Create SCTP transport
    EOE(rawrtc_sctp_transport_create(
            &client->sctp_transport, client->dtls_transport,
            client->local_parameters.sctp_parameters.port,
            data_channel_handler, default_sctp_transport_state_change_handler, client));

    // Get data transport
    EOE(rawrtc_sctp_transport_get_data_transport(
            &client->data_transport, client->sctp_transport));
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
    // Dereference
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
    // Clear data channels
    list_flush(&client->data_channels);

    // Stop all transports & gatherer
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->ws_connection = mem_deref(client->ws_connection);
    client->data_transport = mem_deref(client->data_transport);
    client->sctp_transport = mem_deref(client->sctp_transport);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->ws_socket = mem_deref(client->ws_socket);
    client->http_client = mem_deref(client->http_client);
    client->dns_client = mem_deref(client->dns_client);
    client->gather_options = mem_deref(client->gather_options);
    client->ws_url = mem_deref(client->ws_url);
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

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <0|1 (ice-role)> [<sctp-port>] [<ws-url>] [<ice-candidate-type> ...]",
                  program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    char** ice_candidate_types = NULL;
    size_t n_ice_candidate_types = 0;
    enum rawrtc_ice_role role;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct data_channel_sctp_client client = {0};

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

    // Get WS URL (optional)
    if (argc >= 4) {
        EOE(rawrtc_sdprintf(&client.ws_url, argv[3]));
    } else {
        EOE(rawrtc_sdprintf(&client.ws_url, "ws://217.160.182.235:9765/shell-o-mat/0"));
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 5) {
        ice_candidate_types = &argv[4];
        n_ice_candidate_types = (size_t) argc - 4;
    }

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

    // Set client fields
    client.name = "A";
    client.ice_candidate_types = ice_candidate_types;
    client.n_ice_candidate_types = n_ice_candidate_types;
    client.gather_options = gather_options;
    client.role = role;
    list_init(&client.data_channels);

    // Setup client
    client_init(&client);

    // Start gathering
    client_start_gathering(&client);

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop client & bye
    client_stop(&client);
    before_exit();
    return 0;
}
