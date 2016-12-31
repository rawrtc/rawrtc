#include <stdio.h>
#include <string.h>
#include <rawrtc.h>

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "data-channel-sctp-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

#define EOE(code) exit_on_error(code, __FILE__, __LINE__)
#define EOR(code) exit_on_re_error(code, __FILE__, __LINE__)

struct data_channel;

static struct rawrtc_data_channel_options* data_channel_handler(
    struct rawrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
    void* const arg
);

static void data_channel_open_handler(
    void* const arg
);

static void data_channel_buffered_amount_low_handler(
    void* const arg
);

static void data_channel_error_handler(
    void* const arg
);

static void data_channel_close_handler(
    void* const arg
);

static void data_channel_message_handler(
    struct mbuf* const buffer,
    enum rawrtc_data_channel_message_flag const flags,
    void* const arg
);

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
    struct rawrtc_data_transport* data_transport;
    struct data_channel* data_channel_negotiated;
    struct data_channel* data_channel;
    struct client* other_client;
};

struct data_channel {
    struct client* client;
    struct rawrtc_data_channel* channel;
    char const* label;
};

static void before_exit() {
    // Close
    rawrtc_close();

    // Check memory leaks
    tmr_debug();
    mem_debug();
}

static void exit_on_error(enum rawrtc_code code, char const* const file, uint32_t line) {
    switch (code) {
        case RAWRTC_CODE_SUCCESS:
            return;
        case RAWRTC_CODE_NOT_IMPLEMENTED:
            fprintf(stderr, "Not implemented in %s %"PRIu32"\n",
                    file, line);
            return;
        default:
            fprintf(stderr, "Error in %s %"PRIu32" (%d): %s\n",
                    file, line, code, rawrtc_code_to_str(code));
            before_exit();
            exit((int) code);
    }
}

static void exit_on_re_error(
        int code,
        char const* const file,
        uint32_t line
) {
    if (code != 0) {
        DEBUG_WARNING("Error in %s %"PRIu32" (%d): %s\n", file, line, code, strerror(code));
        before_exit();
        exit(code);
    }
}

static void data_channel_destroy(
        void* const arg
) {
    struct data_channel* const channel = arg;

    // Dereference
    mem_deref(channel->channel);
}

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
        // TODO: Seems that url can be null, fix or handle!
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

            // Create data channel argument
            client->data_channel = mem_zalloc(sizeof(*client->data_channel), data_channel_destroy);
            if (!client->data_channel) {
                EOE(RAWRTC_CODE_NO_MEMORY);
            }
            client->data_channel->client = client;
            client->data_channel->label = "bear-noises";

            // Create data channel parameters
            EOE(rawrtc_data_channel_parameters_create(
                    &channel_parameters, client->data_channel->label,
                    RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED, 0, NULL, false, 0));

            // Create data channel
            EOE(rawrtc_data_channel_create(
                    &client->data_channel->channel, client->data_transport,
                    channel_parameters, NULL,
                    data_channel_open_handler, data_channel_buffered_amount_low_handler,
                    data_channel_error_handler, data_channel_close_handler,
                    data_channel_message_handler, client->data_channel));

            // Dereference
            mem_deref(channel_parameters);
        }
    }
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
}

static struct rawrtc_data_channel_options* data_channel_handler(
        struct rawrtc_data_channel* const data_channel, // read-only, MUST be referenced when used
        void* const arg
) {
    struct client* const client = arg;
    DEBUG_INFO("(%s) New data channel instance\n", client->name);
    return NULL; // Use default options
}

static void data_channel_open_handler(
        void* const arg
) {
    struct data_channel* const channel = arg;
    struct client* const client = channel->client;
    struct mbuf* buffer;
    enum rawrtc_code error;
    DEBUG_PRINTF("(%s) Data channel open: %s\n", client->name, channel->label);

    // Compose message (128 KiB)
    // TODO: Find out why messages > 128 KiB lead to a segmentation fault
    buffer = mbuf_alloc(1 << 17);
    EOE(buffer ? RAWRTC_CODE_SUCCESS : RAWRTC_CODE_NO_MEMORY);
    EOR(mbuf_fill(buffer, 'M', mbuf_get_space(buffer)));
    mbuf_set_pos(buffer, 0);

    // Send message
    DEBUG_PRINTF("Sending %zu bytes\n", mbuf_get_left(buffer));
    error = rawrtc_data_channel_send(channel->channel, buffer, true);
    if (error) {
        DEBUG_WARNING("Could not send, reason: %s\n", rawrtc_code_to_str(error));
    }
    mem_deref(buffer);
}

static void data_channel_buffered_amount_low_handler(
        void* const arg
) {
    struct data_channel* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel buffered amount low: %s\n", client->name, channel->label);
}

static void data_channel_error_handler(
        void* const arg
) {
    struct data_channel* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel error: %s\n", client->name, channel->label);
}

static void data_channel_close_handler(
        void* const arg
) {
    struct data_channel* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Data channel closed: %s\n", client->name, channel->label);
}

static void data_channel_message_handler(
        struct mbuf* const buffer,
        enum rawrtc_data_channel_message_flag const flags,
        void* const arg
) {
    struct data_channel* const channel = arg;
    struct client* const client = channel->client;
    DEBUG_PRINTF("(%s) Incoming message for data channel %s: %"PRIu32" bytes\n",
                 client->name, channel->label, mbuf_get_left(buffer));
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
    struct rawrtc_data_channel_parameters* channel_parameters;

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

    // Get data transport
    EOE(rawrtc_sctp_transport_get_data_transport(
            &local->data_transport, local->sctp_transport));

    // Create data channel argument
    local->data_channel_negotiated = mem_zalloc(
            sizeof(*local->data_channel_negotiated), data_channel_destroy);
    if (!local->data_channel_negotiated) {
        EOE(RAWRTC_CODE_NO_MEMORY);
    }
    local->data_channel_negotiated->client = local;
    local->data_channel_negotiated->label = "cat-noises";

    // Create data channel parameters
    EOE(rawrtc_data_channel_parameters_create(
            &channel_parameters, local->data_channel_negotiated->label,
            RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED, 0, NULL, true, 0));

    // Create pre-negotiated data channel
    EOE(rawrtc_data_channel_create(
            &local->data_channel_negotiated->channel, local->data_transport,
            channel_parameters, NULL,
            data_channel_open_handler, data_channel_buffered_amount_low_handler,
            data_channel_error_handler, data_channel_close_handler, data_channel_message_handler,
            local->data_channel_negotiated));

    // Dereference
    mem_deref(channel_parameters);
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
    if (client->data_channel) {
        EOE(rawrtc_data_channel_close(client->data_channel->channel));
    }
    EOE(rawrtc_data_channel_close(client->data_channel_negotiated->channel));
    EOE(rawrtc_sctp_transport_stop(client->sctp_transport));
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
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
            .data_transport = NULL,
            .data_channel = NULL,
            .data_channel_negotiated = NULL,
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
            .data_transport = NULL,
            .data_channel = NULL,
            .data_channel_negotiated = NULL,
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
    EOE(rawrtc_error_to_code(re_main(signal_handler)));

    // Stop clients
    client_stop(&a);
    client_stop(&b);

    // Free
    mem_deref(gather_options);

    // Bye
    before_exit();
    return 0;
}
