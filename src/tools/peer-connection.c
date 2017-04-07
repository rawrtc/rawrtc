#include <rawrtc.h>
#include "helper/utils.h"
#include "helper/handler.h"

#define DEBUG_MODULE "peer-connection-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

// Note: Shadows struct client
struct peer_connection_client {
    char* name;
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
    struct rawrtc_ice_gather_options* gather_options;
    bool offerer;
    struct rawrtc_peer_connection* connection;
    struct data_channel_helper* data_channel_negotiated;
    struct data_channel_helper* data_channel;
};

static struct tmr timer = {{0}};

static void timer_handler(
        void* arg
) {
    struct data_channel_helper* const channel = arg;
    struct peer_connection_client* const client = (struct peer_connection_client*) channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;

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

    // Close if answerer
    if (!client->offerer) {
        // Close bear-noises
        DEBUG_PRINTF("(%s) Closing channel\n", client->name, channel->label);
        EOR(rawrtc_data_channel_close(client->data_channel->channel));
    }
}

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel_helper* const channel = arg;
    struct peer_connection_client* const client = (struct peer_connection_client*) channel->client;
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

static void peer_connection_state_change_handler(
        enum rawrtc_peer_connection_state const state, // read-only
        void* const arg
) {
    struct peer_connection_client* const client = arg;

    // Print state
    default_peer_connection_state_change_handler(state, arg);

    // Open? Create new channel (if answerer)
    // TODO: Move this once we can create data channels earlier
    if (state == RAWRTC_PEER_CONNECTION_STATE_CONNECTED && !client->offerer) {
        struct rawrtc_data_channel_parameters* channel_parameters;

        // Create data channel helper for in-band negotiated data channel
        data_channel_helper_create(
                &client->data_channel, (struct client *) client, "bear-noises");

        // Create data channel parameters
        EOE(rawrtc_data_channel_parameters_create(
                &channel_parameters, client->data_channel->label,
                RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0));

        // Create data channel
        EOE(rawrtc_peer_connection_create_data_channel(
                &client->data_channel->channel, client->connection, channel_parameters, NULL,
                data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
                default_data_channel_error_handler, default_data_channel_close_handler,
                default_data_channel_message_handler, client->data_channel));

        // Un-reference data channel parameters
        mem_deref(channel_parameters);
    }
}

static void client_init(
        struct peer_connection_client* const client
) {
    struct mbuf* description;
    struct rawrtc_data_channel_parameters* channel_parameters;

    // Create peer connection
    EOE(rawrtc_peer_connection_create(&client->connection, peer_connection_state_change_handler));

    // Create data channel helper for pre-negotiated data channel
    data_channel_helper_create(
            &client->data_channel_negotiated, (struct client *) client, "cat-noises");

    // Create data channel parameters
    EOE(rawrtc_data_channel_parameters_create(
            &channel_parameters, client->data_channel_negotiated->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0));

    // Create pre-negotiated data channel
    EOE(rawrtc_peer_connection_create_data_channel(
            &client->data_channel_negotiated->channel, client->connection, channel_parameters, NULL,
            data_channel_open_handler, default_data_channel_buffered_amount_low_handler,
            default_data_channel_error_handler, default_data_channel_close_handler,
            default_data_channel_message_handler, client->data_channel_negotiated));

    // Un-reference data channel parameters
    mem_deref(channel_parameters);

    // Create offer
    EOE(rawrtc_peer_connection_create_offer(&description, client->connection, true));
    EOE(rawrtc_peer_connection_create_offer(&description, client->connection, false));

    // TODO: ...
//    EOE(rawrtc_peer_connection_set_remote_description(client->connection, description));
}

static void client_stop(
        struct peer_connection_client* const client
) {
//    EOE(rawrtc_peer_connection_stop(client->connection));

    // Un-reference & close
    client->data_channel = mem_deref(client->data_channel);
    client->data_channel_negotiated = mem_deref(client->data_channel_negotiated);
    client->connection = mem_deref(client->connection);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
//    fd_close(STDIN_FILENO);
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <0|1 (offerer)> [<ice-candidate-type> ...]", program);
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
    struct peer_connection_client client = {0};
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

    // Get role
    // Note: We handle it as an ICE role (because that is pretty close)
    if (get_ice_role(&role, argv[1])) {
        exit_with_usage(argv[0]);
    }

    // Get enabled ICE candidate types to be added (optional)
    if (argc >= 3) {
        ice_candidate_types = &argv[2];
        n_ice_candidate_types = (size_t) argc - 2;
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
    client.offerer = role == RAWRTC_ICE_ROLE_CONTROLLING ? true : false;

    // Setup client
    client_init(&client);

    // Listen on stdin
//    EOR(fd_listen(STDIN_FILENO, FD_READ, parse_remote_parameters, &client));

    // Start main loop
    // TODO: Wrap re_main?
    EOR(re_main(default_signal_handler));

    // Stop client & bye
    client_stop(&client);
    before_exit();
    return 0;
}
