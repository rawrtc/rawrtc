#include <string.h> // memcmp
#include <rawrtcc/internal/certificate.h>
#include <rawrtcc/internal/message_buffer.h>
#include <rawrtcc/internal/utils.h>
#include <rawrtc.h>
#include "config.h"
#include "ice_gatherer.h"
#include "ice_transport.h"
#include "dtls_transport.h"
#include "dtls_parameters.h"
#include "candidate_helper.h"

#define DEBUG_MODULE "dtls-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

/*
 * Embedded DH parameters in DER encoding (bits: 2048)
 */
uint8_t const rawrtc_default_dh_parameters[] = {
    0x30, 0x82, 0x01, 0x08, 0x02, 0x82, 0x01, 0x01, 0x00, 0xaa, 0x4c, 0x1f,
    0x1e, 0xc9, 0xed, 0xfe, 0x5c, 0x50, 0x2d, 0xff, 0xf4, 0x95, 0xf4, 0x80,
    0x69, 0xcf, 0xc3, 0x84, 0x29, 0x87, 0xd5, 0x2c, 0x4f, 0xf6, 0x9e, 0x88,
    0xa2, 0x5b, 0x61, 0xd2, 0x7d, 0x78, 0x97, 0xce, 0x47, 0x39, 0x9d, 0xc0,
    0x95, 0x14, 0x98, 0x1f, 0xa9, 0xa3, 0x42, 0x93, 0x58, 0x49, 0x3d, 0xad,
    0xeb, 0x6c, 0x3d, 0x79, 0x2d, 0x27, 0x94, 0x67, 0x4c, 0xdc, 0x94, 0x31,
    0xbf, 0xc1, 0x00, 0x9d, 0x96, 0x4a, 0x91, 0xa7, 0x4f, 0xab, 0x48, 0x44,
    0xcc, 0x54, 0x1a, 0x4e, 0x2a, 0x8e, 0xa1, 0x81, 0x4b, 0xeb, 0xea, 0xc3,
    0xba, 0xd6, 0x03, 0xfb, 0xf2, 0x9a, 0x48, 0x1f, 0xc8, 0xba, 0x73, 0x89,
    0x86, 0x25, 0x2e, 0xba, 0x10, 0x80, 0x2a, 0xeb, 0xf9, 0xe2, 0x28, 0xf1,
    0xcf, 0x85, 0x0d, 0xeb, 0x2f, 0x61, 0x51, 0x11, 0xe1, 0xe7, 0x82, 0xe5,
    0xa7, 0x5d, 0x71, 0x0a, 0xef, 0x8a, 0xe1, 0x97, 0x48, 0x41, 0xac, 0xd7,
    0xc5, 0xf7, 0xce, 0xd5, 0xcd, 0x66, 0x1e, 0x6b, 0x0e, 0x82, 0x4e, 0x77,
    0x5d, 0x89, 0x3b, 0xe2, 0x94, 0x7a, 0x10, 0xee, 0x5b, 0x5d, 0x36, 0x07,
    0x29, 0x8b, 0x06, 0xb6, 0x49, 0x1e, 0x17, 0x17, 0x57, 0xc8, 0xc1, 0x80,
    0x24, 0x15, 0x22, 0x9c, 0xb8, 0x59, 0x55, 0x08, 0x41, 0x67, 0x07, 0xca,
    0xa8, 0x54, 0x1a, 0xd1, 0xb7, 0x91, 0x2f, 0x41, 0x78, 0xc0, 0xcd, 0x2f,
    0x07, 0x49, 0x4b, 0xb9, 0x05, 0xf4, 0xea, 0x72, 0x3a, 0xcf, 0x04, 0x69,
    0xcb, 0x5b, 0xe4, 0xcb, 0x4f, 0x72, 0x40, 0xe4, 0x56, 0x1f, 0xca, 0xee,
    0x33, 0x2b, 0x29, 0x1a, 0x80, 0xda, 0x01, 0x3f, 0x03, 0xa6, 0xbf, 0x32,
    0x02, 0x6c, 0xfb, 0xb1, 0xb5, 0x81, 0xda, 0x32, 0x6f, 0xa1, 0x4b, 0x9f,
    0x42, 0x2e, 0x17, 0xc9, 0x95, 0x30, 0xda, 0x16, 0xb7, 0x9a, 0x7c, 0xf4,
    0x83, 0x02, 0x01, 0x02
};
size_t const rawrtc_default_dh_parameters_length = ARRAY_SIZE(rawrtc_default_dh_parameters);

/*
 * List of default DTLS cipher suites.
 */
char const* rawrtc_default_dtls_cipher_suites[] = {
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-AES128-GCM-SHA256", // recommended
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-SHA256",
    "ECDHE-RSA-AES128-SHA256",
    "ECDHE-ECDSA-AES128-SHA", // required
    "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "DHE-RSA-AES128-SHA256",
    "DHE-RSA-AES128-SHA",
    "DHE-RSA-AES256-SHA256",
    "DHE-RSA-AES256-SHA"
};
size_t const rawrtc_default_dtls_cipher_suites_length =
        ARRAY_SIZE(rawrtc_default_dtls_cipher_suites);

/*
 * Handle outgoing buffered DTLS messages.
 */
static bool dtls_outgoing_buffer_handler(
        struct mbuf* const buffer,
        void* const context,
        void* const arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    enum rawrtc_code error;
    (void) context;

    // Send
    error = rawrtc_dtls_transport_send(transport, buffer);
    if (error) {
        DEBUG_WARNING("Could not send buffered packet, reason: %s\n",
                      rawrtc_code_to_str(error));
    }

    // Continue iterating through message queue
    return true;
}

/*
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_state(
        struct rawrtc_dtls_transport* const transport,
        enum rawrtc_dtls_transport_state const state
) {
    // Closed or failed: Remove connection
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CLOSED
            || state == RAWRTC_DTLS_TRANSPORT_STATE_FAILED) {
        // Remove connection
        transport->connection = mem_deref(transport->connection);

        // Remove self from ICE transport (if attached)
        transport->ice_transport->dtls_transport = NULL;
    }

    // Set state
    transport->state = state;

    // Connected?
    if (state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        // Send buffered outgoing DTLS messages
        enum rawrtc_code const error = rawrtc_message_buffer_clear(
                &transport->buffered_messages_out, dtls_outgoing_buffer_handler, transport);
        if (error) {
            DEBUG_WARNING("Could not send buffered messages, reason: %s\n",
                          rawrtc_code_to_str(error));
        }
    }

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }
}

/*
 * Check if the state is 'closed' or 'failed'.
 */
static bool is_closed(
        struct rawrtc_dtls_transport* const transport // not checked
) {
    switch (transport->state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_CLOSED:
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            return true;
        default:
            return false;
    }
}

/*
 * DTLS connection closed handler.
 */
static void close_handler(
        int err,
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    enum rawrtc_code error;

    // Closed?
    if (!is_closed(transport)) {
        DEBUG_INFO("DTLS connection closed, reason: %m\n", err);

        // Set to failed if not closed normally
        if (err != ECONNRESET) {
            set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_FAILED);
        }

        // Stop
        error = rawrtc_dtls_transport_stop(transport);
        if (error) {
            DEBUG_WARNING("DTLS connection closed, could not stop transport: %s\n",
                          rawrtc_code_to_str(error));
        }
    } else {
        DEBUG_PRINTF("DTLS connection closed (but state is already closed anyway), reason: %m\n",
                     err);
    }
}

/*
 * Handle incoming DTLS messages.
 */
static void dtls_receive_handler(
        struct mbuf* buffer,
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;

    // Check state
    if (is_closed(transport)) {
        DEBUG_PRINTF("Ignoring incoming DTLS message, transport is closed\n");
        return;
    }

    // Handle (if receive handler exists and connected)
    // Note: Checking for 'connected' state ensures that no data will be received before the
    //       fingerprints have been verified.
    if (transport->receive_handler && transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        transport->receive_handler(buffer, transport->receive_handler_arg);
        return;
    }

    // Buffer message
    enum rawrtc_code error = rawrtc_message_buffer_append(
            &transport->buffered_messages_in, buffer, NULL);
    if (error) {
        DEBUG_WARNING("Could not buffer incoming packet, reason: %s\n",
                      rawrtc_code_to_str(error));
    } else {
        DEBUG_PRINTF("Buffered incoming packet of size %zu\n", mbuf_get_left(buffer));
    }
}

/*
 * Either called by a DTLS connection established event or by the
 * `start` method of the DTLS transport.
 * The caller MUST make sure that remote parameters are available and
 * that the state is NOT 'closed' or 'failed'!
 */
static void verify_certificate(
        struct rawrtc_dtls_transport* const transport // not checked
) {
    size_t i;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    bool valid = false;
    enum tls_fingerprint algorithm;
    uint8_t expected_fingerprint[RAWRTC_FINGERPRINT_MAX_SIZE];
    uint8_t actual_fingerprint[RAWRTC_FINGERPRINT_MAX_SIZE];

    // Verify the peer's certificate
    // TODO: Fix this. Testing the fingerprint alone is okay for now though.
//    error = rawrtc_error_to_code(tls_peer_verify(transport->connection));
//    if (error) {
//        goto out;
//    }
//    DEBUG_PRINTF("Peer's certificate verified\n");

    // Check if any of the fingerprints provided matches
    // TODO: Is this correct?
    for (i = 0; i < transport->remote_parameters->fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint =
                transport->remote_parameters->fingerprints->fingerprints[i];
        size_t length;
        size_t bytes_written;

        // Get algorithm
        error = rawrtc_certificate_sign_algorithm_to_tls_fingerprint(
                &algorithm, fingerprint->algorithm);
        if (error) {
            if (error == RAWRTC_CODE_UNSUPPORTED_ALGORITHM) {
                continue;
            }
            goto out;
        }

        // Get algorithm digest size
        error = rawrtc_get_sign_algorithm_length(&length, fingerprint->algorithm);
        if (error) {
            if (error == RAWRTC_CODE_UNSUPPORTED_ALGORITHM) {
                continue;
            }
            goto out;
        }

        // Convert hex-encoded value to binary
        error = rawrtc_colon_hex_to_bin(
                &bytes_written, expected_fingerprint, length, fingerprint->value);
        if (error) {
            if (error == RAWRTC_CODE_INSUFFICIENT_SPACE) {
                DEBUG_WARNING("Hex-encoded fingerprint exceeds buffer size!\n");
            } else {
                DEBUG_WARNING("Could not convert hex-encoded fingerprint to binary, reason: %s\n",
                        rawrtc_code_to_str(error));
            }
            continue;
        }

        // Validate length
        if (bytes_written != length) {
            DEBUG_WARNING("Hex-encoded fingerprint should have been %zu bytes but was %zu bytes\n",
                    length, bytes_written);
            continue;
        }

        // Get remote fingerprint
        error = rawrtc_error_to_code(tls_peer_fingerprint(
                transport->connection, algorithm, actual_fingerprint, sizeof(actual_fingerprint)));
        if (error) {
            goto out;
        }

        // Compare fingerprints
        // TODO: Constant-time equality comparison needed?
        if (memcmp(expected_fingerprint, actual_fingerprint, length) == 0) {
            DEBUG_PRINTF("Peer's certificate fingerprint is valid\n");
            valid = true;
        }
    }

out:
    if (error || !valid) {
        DEBUG_WARNING("Verifying certificate failed, reason: %s\n", rawrtc_code_to_str(error));
        if (!is_closed(transport)) {
            set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_FAILED);
        }

        // Stop
        error = rawrtc_dtls_transport_stop(transport);
        if (error) {
            DEBUG_WARNING("DTLS connection closed, could not stop transport: %s\n",
                          rawrtc_code_to_str(error));
        }
    } else {
        // Connected
        set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED);
    }
}

/*
 * Handle DTLS connection established event.
 */
static void establish_handler(
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;

    // Check state
    if (is_closed(transport)) {
        DEBUG_WARNING("Ignoring established DTLS connection, transport is closed\n");
        return;
    }

    // Connection established
    // Note: State is either 'NEW', 'CONNECTING' or 'FAILED' here
    DEBUG_INFO("DTLS connection established\n");
    transport->connection_established = true;

    // Verify certificate & fingerprint (if remote parameters are available)
    if (transport->remote_parameters) {
        verify_certificate(transport);
    }
}

/*
 * Handle incoming DTLS connection.
 */
static void connect_handler(
        const struct sa* peer,
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    bool role_is_server;
    bool have_connection;
    int err;
    (void) peer;

    // Check state
    if (is_closed(transport)) {
        DEBUG_PRINTF("Ignoring incoming DTLS connection, transport is closed\n");
        return;
    }

    // Update role if "auto"
    if (transport->role == RAWRTC_DTLS_ROLE_AUTO) {
        DEBUG_PRINTF("Switching role 'auto' -> 'server'\n");
        transport->role = RAWRTC_DTLS_ROLE_SERVER;
    }
    
    // Accept?
    role_is_server = transport->role == RAWRTC_DTLS_ROLE_SERVER;
    have_connection = transport->connection != NULL;
    if (role_is_server && !have_connection) {
        // Set state to connecting (if not already set)
        if (transport->state != RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING) {
            set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING);
        }

        // Accept and create connection
        DEBUG_PRINTF("Accepting incoming DTLS connection from %J\n", peer);
        err = dtls_accept(&transport->connection, transport->context, transport->socket,
                          establish_handler, dtls_receive_handler, close_handler, transport);
        if (err) {
            DEBUG_WARNING("Could not accept incoming DTLS connection, reason: %m\n", err);
        }
    } else {
        if (have_connection) {
            DEBUG_WARNING("Incoming DTLS connect but we already have a connection\n");
        }
        if (!role_is_server) {
            DEBUG_WARNING("Incoming DTLS connect but role is 'client'\n");
        }
    }
}

/*
 * Initiate a DTLS connect.
 */
static enum rawrtc_code do_connect(
        struct rawrtc_dtls_transport* const transport,
        const struct sa* const peer
) {
    // Connect
    DEBUG_PRINTF("Starting DTLS connection to %J\n", peer);
    return rawrtc_error_to_code(dtls_connect(
            &transport->connection, transport->context, transport->socket, peer,
            establish_handler, dtls_receive_handler, close_handler, transport));
}

/*
 * Handle outgoing DTLS messages.
 */
static int send_handler(
        struct tls_conn* tc,
        struct sa const* original_destination,
        struct mbuf* buffer,
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    struct trice* const ice = transport->ice_transport->gatherer->ice;
    bool closed = is_closed(transport);
    (void) tc; (void) original_destination;

    // Note: No need to check if closed as only non-application data may be sent if the
    //       transport is already closed.

    // Get selected candidate pair
    struct ice_candpair* const candidate_pair = list_ledata(list_head(trice_validl(ice)));
    if (!candidate_pair) {
        if (!closed) {
            DEBUG_WARNING("Cannot send message, no selected candidate pair\n");
        }
        return ECONNRESET;
    }

    // Get local candidate's UDP socket
    // TODO: What about TCP?
    struct udp_sock* const udp_socket = trice_lcand_sock(ice, candidate_pair->lcand);
    if (!udp_socket) {
        if (!closed) {
            DEBUG_WARNING("Cannot send message, selected candidate pair has no socket\n");
        }
        return ECONNRESET;
    }

    // Send
    // TODO: Is destination correct?
    DEBUG_PRINTF("Sending DTLS message (%zu bytes) to %J (originally: %J) from %J\n",
                 mbuf_get_left(buffer), &candidate_pair->rcand->attr.addr, original_destination,
                 &candidate_pair->lcand->attr.addr);
    int err = udp_send(udp_socket, &candidate_pair->rcand->attr.addr, buffer);
    if (err) {
        DEBUG_WARNING("Could not send, error: %m\n", err);
    }
    return err;
}

/*
 * Handle MTU queries.
 */
static size_t mtu_handler(
        struct tls_conn* tc,
        void* arg
) {
    (void) tc; (void) arg;
    // TODO: Choose a sane value.
    return 1400;
}

/*
 * Handle received UDP messages.
 */
static bool udp_receive_handler(
        struct mbuf* const buffer,
        void* const context,
        void* const arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    struct sa* source = context;
    struct sa const* peer;

    // TODO: Check if DTLS or SRTP packet
    // TODO: This handler should also be moved into ICE transport
    // https://tools.ietf.org/search/rfc7983#section-7

    // Update remote peer address (if changed and connection exists)
    if (transport->connection) {
        // TODO: It would be cleaner to check if source is in our list of remote candidates

        // TODO: SCTP - Retest path MTU and reset congestion state to the initial state
        // https://tools.ietf.org/html/draft-ietf-rtcweb-data-channel-13#section-5

        // Update if changed
        peer = dtls_peer(transport->connection);
        if (!sa_cmp(peer, source, SA_ALL)) {
            DEBUG_PRINTF("Remote changed its peer address from %J to %J\n", peer, source);
            dtls_set_peer(transport->connection, source);
        }
    }

    // Decrypt & receive
    // Note: No need to check if the transport is already closed as the messages will re-appear in
    //       the `dtls_receive_handler`.
    dtls_receive(transport->socket, source, buffer);

    // Continue iterating through message queue
    return true;
}

/*
 * Handle received UDP messages (UDP receive helper).
 */
static bool udp_receive_helper(
        struct sa* source,
        struct mbuf* buffer,
        void* arg
) {
    // Receive
    udp_receive_handler(buffer, source, arg);

    // Handled
    return true;
}

/*
 * Destructor for an existing DTLS transport.
 */
static void rawrtc_dtls_transport_destroy(
        void* arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    struct le* le;

    // Stop transport
    // TODO: Check effects in case transport has been destroyed due to error in create
    rawrtc_dtls_transport_stop(transport);

    // TODO: Remove once ICE transport and DTLS transport have been separated properly
    for (le = list_head(&transport->ice_transport->gatherer->local_candidates);
         le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate_helper = le->data;
        mem_deref(candidate_helper->udp_helper);
        // TODO: Be aware that UDP packets go to nowhere now...
    }

    // Un-reference
    mem_deref(transport->connection);
    mem_deref(transport->socket);
    mem_deref(transport->context);
    list_flush(&transport->fingerprints);
    list_flush(&transport->buffered_messages_out);
    list_flush(&transport->buffered_messages_in);
    mem_deref(transport->remote_parameters);
    list_flush(&transport->certificates);
    mem_deref(transport->ice_transport);
}

/*
 * Create a new DTLS transport (internal)
 */
enum rawrtc_code rawrtc_dtls_transport_create_internal(
        struct rawrtc_dtls_transport** const transportp, // de-referenced
        struct rawrtc_ice_transport* const ice_transport, // referenced
        struct list* certificates, // de-referenced, copied (shallow)
        rawrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
        rawrtc_dtls_transport_error_handler* const error_handler, // nullable
        void* const arg // nullable
) {
    struct rawrtc_dtls_transport* transport;
    enum rawrtc_code error;
    struct le* le;
    struct rawrtc_certificate* certificate;
    uint8_t* certificate_der;
    size_t certificate_der_length;

    // Check arguments
    if (!transportp || !ice_transport || !certificates) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check certificates expiration dates

    // Check ICE transport state
    if (ice_transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Check if another DTLS transport is associated to the ICE transport
    if (ice_transport->dtls_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), rawrtc_dtls_transport_destroy);
    if (!transport) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = RAWRTC_DTLS_TRANSPORT_STATE_NEW; // TODO: Raise state (delayed)?
    transport->ice_transport = mem_ref(ice_transport);
    transport->certificates = *certificates;
    transport->state_change_handler = state_change_handler;
    transport->error_handler = error_handler;
    transport->arg = arg;
    transport->role = RAWRTC_DTLS_ROLE_AUTO;
    transport->connection_established = false;
    list_init(&transport->buffered_messages_in);
    list_init(&transport->buffered_messages_out);
    list_init(&transport->fingerprints);

    // Create (D)TLS context
    DEBUG_PRINTF("Creating DTLS context\n");
    error = rawrtc_error_to_code(tls_alloc(&transport->context, TLS_METHOD_DTLS, NULL, NULL));
    if (error) {
        goto out;
    }

    // Get DER encoded certificate of choice
    // TODO: Which certificate should we use?
    certificate = list_ledata(list_head(&transport->certificates));
    error = rawrtc_certificate_get_der(
            &certificate_der, &certificate_der_length, certificate, RAWRTC_CERTIFICATE_ENCODE_BOTH);
    if (error) {
        goto out;
    }

    // Set certificate
    DEBUG_PRINTF("Setting certificate on DTLS context\n");
    error = rawrtc_error_to_code(tls_set_certificate_der(
            transport->context, rawrtc_certificate_key_type_to_tls_keytype(certificate->key_type),
            certificate_der, certificate_der_length, NULL, 0));
    mem_deref(certificate_der);
    if (error) {
        goto out;
    }

    // Set Diffie-Hellman parameters
    // TODO: Get DH params from config
    DEBUG_PRINTF("Setting DH parameters on DTLS context\n");
    error = rawrtc_error_to_code(tls_set_dh_params_der(
            transport->context, rawrtc_default_dh_parameters, rawrtc_default_dh_parameters_length));
    if (error) {
        goto out;
    }

    // Set cipher suites
    // TODO: Get cipher suites from config
    DEBUG_PRINTF("Setting cipher suites on DTLS context\n");
    error = rawrtc_error_to_code(tls_set_ciphers(
            transport->context, rawrtc_default_dtls_cipher_suites,
            rawrtc_default_dtls_cipher_suites_length));
    if (error) {
        goto out;
    }

    // Send client certificate (client) / request client certificate (server)
    tls_set_verify_client(transport->context);

    // Create DTLS socket
    DEBUG_PRINTF("Creating DTLS socket\n");
    error = rawrtc_error_to_code(dtls_socketless(
            &transport->socket, 1, connect_handler, send_handler, mtu_handler, transport));
    if (error) {
        goto out;
    }

    // Attach to existing candidate pairs
    for (le = list_head(trice_validl(ice_transport->gatherer->ice)); le != NULL; le = le->next) {
        struct ice_candpair* candidate_pair = le->data;
        error = rawrtc_dtls_transport_add_candidate_pair(transport, candidate_pair);
        if (error) {
            DEBUG_WARNING("DTLS transport could not attach to candidate pair, reason: %s\n",
                          rawrtc_code_to_str(error));
            goto out;
        }
    }

    // Attach to ICE transport
    // Note: We cannot reference ourselves here as that would introduce a cyclic reference
    ice_transport->dtls_transport = transport;

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

/*
 * Create a new DTLS transport.
 * `*transport` must be unreferenced.
 */
enum rawrtc_code rawrtc_dtls_transport_create(
        struct rawrtc_dtls_transport** const transportp, // de-referenced
        struct rawrtc_ice_transport* const ice_transport, // referenced
        struct rawrtc_certificate* const certificates[], // copied (each item)
        size_t const n_certificates,
        rawrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
        rawrtc_dtls_transport_error_handler* const error_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    struct list certificates_list = LIST_INIT;

    // Append and reference certificates
    error = rawrtc_certificate_array_to_list(&certificates_list, certificates, n_certificates);
    if (error) {
        return error;
    }

    // Create DTLS transport
    return rawrtc_dtls_transport_create_internal(
            transportp, ice_transport, &certificates_list, state_change_handler, error_handler,
            arg);
}

/*
 * Let the DTLS transport attach itself to a candidate pair.
 * TODO: Separate ICE transport and DTLS transport properly (like data transport)
 */
enum rawrtc_code rawrtc_dtls_transport_add_candidate_pair(
        struct rawrtc_dtls_transport* const transport,
        struct ice_candpair* const candidate_pair
) {
    enum rawrtc_code error;
    struct rawrtc_candidate_helper* candidate_helper = NULL;
    
    // Check arguments
    if (!transport || !candidate_pair) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (is_closed(transport)) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // TODO: Check if already attached

    // Find candidate helper
    error = rawrtc_candidate_helper_find(
            &candidate_helper, &transport->ice_transport->gatherer->local_candidates,
            candidate_pair->lcand);
    if (error) {
        DEBUG_WARNING("Could not find matching candidate helper for candidate pair, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Receive buffered packets
    error = rawrtc_message_buffer_clear(
            &transport->ice_transport->gatherer->buffered_messages, udp_receive_handler, transport);
    if (error) {
        DEBUG_WARNING("Could not handle buffered packets on candidate pair, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Attach this transport's receive handler
    error = rawrtc_candidate_helper_set_receive_handler(
            candidate_helper, udp_receive_helper, transport);
    if (error) {
        DEBUG_WARNING("Could not find matching candidate helper for candidate pair, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

    // Do connect (if client and no connection)
    if (transport->role == RAWRTC_DTLS_ROLE_CLIENT && !transport->connection) {
        error = do_connect(transport, &candidate_pair->rcand->attr.addr);
        if (error) {
            DEBUG_WARNING("Could not start DTLS connection for candidate pair, reason: %s\n",
                          rawrtc_code_to_str(error));
            goto out;
        }
    }

out:
    if (!error) {
        DEBUG_PRINTF("Attached DTLS transport to candidate pair\n");
    }
    return error;
}

/*
 * Start the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_start(
        struct rawrtc_dtls_transport* const transport,
        struct rawrtc_dtls_parameters* const remote_parameters // referenced
) {
    enum rawrtc_code error;
    enum rawrtc_ice_role ice_role;

    // Check arguments
    if (!transport || !remote_parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate parameters
    if (remote_parameters->fingerprints->n_fingerprints < 1) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    // Note: Checking for 'remote_parameters' ensures that 'start' is not called twice
    if (transport->remote_parameters || is_closed(transport)) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Set state to connecting (if not already set)
    if (transport->state != RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING) {
        set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING);
    }

    // Get ICE role
    error = rawrtc_ice_transport_get_role(&ice_role, transport->ice_transport);
    if (error) {
        return error;
    }

    // Determine role
    if (remote_parameters->role == RAWRTC_DTLS_ROLE_AUTO) {
        switch (ice_role) {
            case RAWRTC_ICE_ROLE_CONTROLLED:
                transport->role = RAWRTC_DTLS_ROLE_CLIENT;
                DEBUG_PRINTF("Switching role 'auto' -> 'client'\n");
                break;
            case RAWRTC_ICE_ROLE_CONTROLLING:
                transport->role = RAWRTC_DTLS_ROLE_SERVER;
                DEBUG_PRINTF("Switching role 'auto' -> 'server'\n");
                break;
            default:
                // Cannot continue if ICE transport role is unknown
                DEBUG_WARNING("ICE role must be set before DTLS transport can be started!\n");
                return RAWRTC_CODE_INVALID_STATE;
        }
    } else if (remote_parameters->role == RAWRTC_DTLS_ROLE_SERVER) {
        transport->role = RAWRTC_DTLS_ROLE_CLIENT;
        DEBUG_PRINTF("Switching role 'server' -> 'client'\n");
    } else {
        transport->role = RAWRTC_DTLS_ROLE_SERVER;
        DEBUG_PRINTF("Switching role 'client' -> 'server'\n");
    }

    // Connect (if client)
    if (transport->role == RAWRTC_DTLS_ROLE_CLIENT) {
        // Reset existing connections
        if (transport->connection) {
            // Note: This is needed as ORTC requires us to reset previous DTLS connections
            //       if the remote role is 'server'
            DEBUG_PRINTF("Resetting DTLS connection\n");
            transport->connection = mem_deref(transport->connection);
            transport->connection_established = false;
        }

        // Get selected candidate pair
        struct ice_candpair* const candidate_pair = list_ledata(list_head(trice_validl(
                transport->ice_transport->gatherer->ice)));

        // Do connect (if we have a valid candidate pair)
        if (candidate_pair) {
            error = do_connect(transport, &candidate_pair->rcand->attr.addr);
            if (error) {
                goto out;
            }
        }
    } else {
        // Verify certificate & fingerprint (if connection is established)
        if (transport->connection_established) {
            verify_certificate(transport);
        }
    }

out:
    if (error) {
        transport->connection = mem_deref(transport->connection);
    } else {
        // Set remote parameters
        transport->remote_parameters = mem_ref(remote_parameters);
    }
    return error;
}

/*
 * Check for an existing data transport (on top of DTLS).
 */
enum rawrtc_code rawrtc_dtls_transport_have_data_transport(
        bool* const have_data_transportp, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!have_data_transportp || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check if a receive handler has been set.
    if (transport->receive_handler) {
        *have_data_transportp = true;
    } else {
        *have_data_transportp = false;
    }
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Pipe buffered messages into the data receive handler that has a
 * different signature.
 */
static bool intermediate_receive_handler(
        struct mbuf* const buffer,
        void* const context,
        void* const arg
) {
    struct rawrtc_dtls_transport* const transport = arg;
    (void) context;

    // Pipe into the actual receive handler
    if (transport->receive_handler) {
        transport->receive_handler(buffer, transport->receive_handler_arg);
    } else {
        DEBUG_WARNING("No receive handler, discarded %zu bytes\n", mbuf_get_left(buffer));
    }

    // Continue iterating through message queue
    return true;
}

/*
 * Set a data transport on the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_set_data_transport(
        struct rawrtc_dtls_transport* const transport,
        rawrtc_dtls_transport_receive_handler* const receive_handler,
        void* const arg
) {
    enum rawrtc_code error;
    bool have_data_transport;

    // Check arguments
    if (!transport || !receive_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check for existing data transport
    error = rawrtc_dtls_transport_have_data_transport(&have_data_transport, transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Set handler
    transport->receive_handler = receive_handler;
    transport->receive_handler_arg = arg;

    // Receive buffered messages
    error = rawrtc_message_buffer_clear(
            &transport->buffered_messages_in, intermediate_receive_handler, transport);
    if (error) {
        return error;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Remove an existing data transport from the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_clear_data_transport(
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Clear buffered messages (?)

    // Clear handler and argument
    transport->receive_handler = NULL;
    transport->receive_handler_arg = NULL;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Send a data message over the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_send(
        struct rawrtc_dtls_transport* const transport,
        struct mbuf* const buffer
) {
    enum rawrtc_code error;

    // Check arguments
    if (!transport || !buffer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (is_closed(transport)) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Connected?
    if (transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        return rawrtc_error_to_code(dtls_send(transport->connection, buffer));
    }

    // Buffer message
    error = rawrtc_message_buffer_append(&transport->buffered_messages_out, buffer, NULL);
    if (error) {
        DEBUG_WARNING("Could not buffer outgoing packet, reason: %s\n",
                      rawrtc_code_to_str(error));
        return error;
    }

    // Buffered message
    DEBUG_PRINTF("Buffered outgoing packet of size %zu\n", mbuf_get_left(buffer));
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Stop and close the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_stop(
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (is_closed(transport)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Update state
    set_state(transport, RAWRTC_DTLS_TRANSPORT_STATE_CLOSED);
    return RAWRTC_CODE_SUCCESS;

    // TODO: Anything missing?
}

/*
 * Get the current state of the DTLS transport.
 */
enum rawrtc_code rawrtc_dtls_transport_get_state(
        enum rawrtc_dtls_transport_state* const statep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state & done
    *statep = transport->state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get local DTLS parameters of a transport.
 */
enum rawrtc_code rawrtc_dtls_transport_get_local_parameters(
        struct rawrtc_dtls_parameters** const parametersp, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // TODO: Get config from struct
    enum rawrtc_certificate_sign_algorithm const algorithm = rawrtc_default_config.sign_algorithm;
    struct le* le;
    struct rawrtc_dtls_fingerprint* fingerprint;
    enum rawrtc_code error;

    // Check arguments
    if (!parametersp || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (is_closed(transport)) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Lazy-create fingerprints
    if (list_isempty(&transport->fingerprints)) {
        for (le = list_head(&transport->certificates); le != NULL; le = le->next) {
            struct rawrtc_certificate* certificate = le->data;

            // Create fingerprint
            error = rawrtc_dtls_fingerprint_create_empty(&fingerprint, algorithm);
            if (error) {
                return error;
            }

            // Get and set fingerprint of certificate
            error = rawrtc_certificate_get_fingerprint(&fingerprint->value, certificate, algorithm);
            if (error) {
                return error;
            }

            // Append fingerprint
            list_append(&transport->fingerprints, &fingerprint->le, fingerprint);
        }
    }

    // Create and return DTLS parameters instance
    return rawrtc_dtls_parameters_create_internal(
            parametersp, transport->role, &transport->fingerprints);
}

/*
 * Get external DTLS role.
 */
enum rawrtc_code rawrtc_dtls_transport_get_external_role(
        enum rawrtc_external_dtls_role* const rolep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!rolep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert role
    switch (transport->role) {
        case RAWRTC_DTLS_ROLE_AUTO:
            // Unable to convert in this state
            return RAWRTC_CODE_INVALID_STATE;
        case RAWRTC_DTLS_ROLE_CLIENT:
            *rolep = RAWRTC_EXTERNAL_DTLS_ROLE_CLIENT;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_ROLE_SERVER:
            *rolep = RAWRTC_EXTERNAL_DTLS_ROLE_SERVER;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_UNKNOWN_ERROR;
    }
}

/*
 * Convert DTLS transport state to external DTLS transport state.
 */
enum rawrtc_code rawrtc_dtls_transport_get_external_state(
        enum rawrtc_external_dtls_transport_state* const statep, // de-referenced
        struct rawrtc_dtls_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Convert DTLS transport state to external DTLS transport state
    switch (transport->state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_NEW:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_NEW_OR_CONNECTING;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_NEW_OR_CONNECTING;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CONNECTED;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_CLOSED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CLOSED_OR_FAILED;
            return RAWRTC_CODE_SUCCESS;
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            *statep = RAWRTC_EXTERNAL_DTLS_TRANSPORT_STATE_CLOSED_OR_FAILED;
            return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const rawrtc_dtls_transport_state_to_name(
        enum rawrtc_dtls_transport_state const state
) {
    switch (state) {
        case RAWRTC_DTLS_TRANSPORT_STATE_NEW:
            return "new";
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            return "connecting";
        case RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case RAWRTC_DTLS_TRANSPORT_STATE_CLOSED:
            return "closed";
        case RAWRTC_DTLS_TRANSPORT_STATE_FAILED:
            return "failed";
        default:
            return "???";
    }
}

static enum rawrtc_dtls_role const map_enum_dtls_role[] = {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER,
};

static char const * const map_str_dtls_role[] = {
    "auto",
    "client",
    "server",
};

static size_t const map_dtls_role_length = ARRAY_SIZE(map_enum_dtls_role);

/*
 * Translate a DTLS role to str.
 */
char const * rawrtc_dtls_role_to_str(
        enum rawrtc_dtls_role const role
) {
    size_t i;

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (map_enum_dtls_role[i] == role) {
            return map_str_dtls_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to a DTLS role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_dtls_role(
        enum rawrtc_dtls_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_dtls_role_length; ++i) {
        if (str_casecmp(map_str_dtls_role[i], str) == 0) {
            *rolep = map_enum_dtls_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}
