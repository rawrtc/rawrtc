#include <anyrtc.h>
#include "dtls_transport.h"
#include "certificate.h"
#include "utils.h"

#define DEBUG_MODULE "dtls-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Embedded DH parameters (bits: 2048)
 */
char const anyrtc_default_dh_parameters[] = ""
    "-----BEGIN DH PARAMETERS-----\n"
    "MIIBCAKCAQEAqkwfHsnt/lxQLf/0lfSAac/DhCmH1SxP9p6Iolth0n14l85HOZ3A\n"
    "lRSYH6mjQpNYST2t62w9eS0nlGdM3JQxv8EAnZZKkadPq0hEzFQaTiqOoYFL6+rD\n"
    "utYD+/KaSB/IunOJhiUuuhCAKuv54ijxz4UN6y9hURHh54Llp11xCu+K4ZdIQazX\n"
    "xffO1c1mHmsOgk53XYk74pR6EO5bXTYHKYsGtkkeFxdXyMGAJBUinLhZVQhBZwfK\n"
    "qFQa0beRL0F4wM0vB0lLuQX06nI6zwRpy1vky09yQORWH8ruMyspGoDaAT8Dpr8y\n"
    "Amz7sbWB2jJvoUufQi4XyZUw2ha3mnz0gwIBAg==\n"
    "-----END DH PARAMETERS-----";
size_t const anyrtc_default_dh_parameters_length =
        sizeof(anyrtc_default_dh_parameters) / sizeof(*anyrtc_default_dh_parameters);

/*
 * List of default DTLS cipher suites.
 */
char const* anyrtc_default_dtls_cipher_suites[] = {
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
size_t const anyrtc_default_dtls_cipher_suites_length =
        sizeof(anyrtc_default_dtls_cipher_suites) / sizeof(*anyrtc_default_dtls_cipher_suites);

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const anyrtc_dtls_transport_state_to_name(
        enum anyrtc_dtls_transport_state const state
) {
    switch (state) {
        case ANYRTC_DTLS_TRANSPORT_STATE_NEW:
            return "new";
        case ANYRTC_DTLS_TRANSPORT_STATE_CONNECTING:
            return "connecting";
        case ANYRTC_DTLS_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case ANYRTC_DTLS_TRANSPORT_STATE_CLOSED:
            return "closed";
        case ANYRTC_DTLS_TRANSPORT_STATE_FAILED:
            return "failed";
        default:
            return "???";
    }
}

/*
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 */
static enum anyrtc_code set_state(
        struct anyrtc_dtls_transport* const transport,
        enum anyrtc_dtls_transport_state const state
) {
    // Set state
    transport->state = state;

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }

    return ANYRTC_CODE_SUCCESS;
}

static void connect_handler(
        const struct sa* const peer,
        void* const arg
) {
    struct anyrtc_dtls_transport* transport = arg;

    // Check state
    if (transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED) {
        return;
    }

    // Role set?
    // TODO: If role is not determined, buffer incoming connect request

    // Server role?
    // TODO: If server role, accept, if not ignore
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_dtls_transport_destroy(void* arg) {
    struct anyrtc_dtls_transport* transport = arg;

    // Remove from ICE transport
    if (transport->ice_transport) {
        transport->ice_transport->dtls_transport = NULL;
    }

    // Dereference
    list_flush(&transport->certificates);
    mem_deref(transport->socket);
    mem_deref(transport->context);
    mem_deref(transport->ice_transport);
}

/*
 * Create a new DTLS transport.
 */
enum anyrtc_code anyrtc_dtls_transport_create(
        struct anyrtc_dtls_transport** const transportp, // de-referenced
        struct anyrtc_ice_transport* const ice_transport, // referenced
        struct anyrtc_certificate* const certificates[], // copied (each item)
        size_t const n_certificates,
        anyrtc_dtls_transport_state_change_handler* const state_change_handler, // nullable
        anyrtc_dtls_transport_error_handler* const error_handler, // nullable
        void* const arg // nullable
) {
    struct anyrtc_dtls_transport* transport;
    size_t i;
    struct anyrtc_certificate* certificate;
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;
    struct le* le;
    uint8_t* certificate_der;
    size_t certificate_der_length;

    // Check arguments
    if (!transportp || !ice_transport || !certificates || !n_certificates) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Check certificates expiration dates

    // Check ICE transport state
    if (ice_transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Check if another DTLS transport is associated to the ICE transport
    if (ice_transport->dtls_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(struct anyrtc_dtls_transport),
                           anyrtc_dtls_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = ANYRTC_DTLS_TRANSPORT_STATE_NEW;
    transport->ice_transport = mem_ref(ice_transport);
    list_init(&transport->certificates);
    transport->state_change_handler = state_change_handler;
    transport->error_handler = error_handler;
    transport->arg = arg;

    // Append and reference certificates
    for (i = 0; i < n_certificates; ++i) {
        // Copy certificate
        // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
        error = anyrtc_certificate_copy(&certificate, certificates[i]);
        if (error) {
            goto out;
        }

        // Append to list
        list_append(&transport->certificates, &certificate->le, certificate);
    }

    // Create (D)TLS context
    DEBUG_PRINTF("Creating DTLS context\n");
    error = anyrtc_translate_re_code(tls_alloc(&transport->context, TLS_METHOD_DTLS, NULL, NULL));
    if (error) {
        goto out;
    }

    // Get DER encoded certificate of choice
    // TODO: Which certificate should we use?
    certificate = list_ledata(list_head(&transport->certificates));
    error = anyrtc_certificate_get_der(
            &certificate_der, &certificate_der_length, certificate, ANYRTC_CERTIFICATE_ENCODE_BOTH);
    if (error) {
        goto out;
    }

    // Set certificate
    DEBUG_PRINTF("Setting certificate on DTLS context\n");
    error = anyrtc_translate_re_code(tls_set_certificate_der(
            transport->context, anyrtc_translate_certificate_key_type(certificate->key_type),
            certificate_der, certificate_der_length, NULL, 0));
    mem_deref(certificate_der);
    if (error) {
        goto out;
    }

    // Set Diffie-Hellman parameters
    // TODO: Get DH params from config
    DEBUG_PRINTF("Setting DH parameters on DTLS context\n");
    error = anyrtc_translate_re_code(tls_set_dh_params_pem(transport->context,
            anyrtc_default_dh_parameters, anyrtc_default_dh_parameters_length));
    if (error) {
        goto out;
    }

    // Set cipher suites
    // TODO: Get cipher suites from config
    DEBUG_PRINTF("Setting cipher suites on DTLS context\n");
    error = anyrtc_translate_re_code(tls_set_ciphers(transport->context,
            anyrtc_default_dtls_cipher_suites, anyrtc_default_dtls_cipher_suites_length));
    if (error) {
        goto out;
    }

    // Send client certificate (client) / request client certificate (server)
    tls_set_verify_client(transport->context);

//    // Create DTLS socket
//    DEBUG_PRINTF("Creating DTLS socket\n");
//    error = anyrtc_translate_re_code(dtls_socketless(
//            &transport->socket, 0, connect_handler, send_handler, mtu_handler, transport));
//    if (error) {
//        goto out;
//    }

    // Attach to existing candidate pairs
    for (le = list_head(trice_validl(ice_transport->gatherer->ice)); le != NULL; le = le->next) {
        struct ice_candpair* candidate_pair = le->data;
        error = anyrtc_dtls_transport_add_candidate_pair(transport, candidate_pair);
        if (error) {
            // TODO: Convert error code to string
            DEBUG_WARNING("DTLS transport could not attach to candidate pair, reason: %d\n", error);
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
 * Let the DTLS transport attach itself to a candidate pair.
 */
enum anyrtc_code anyrtc_dtls_transport_add_candidate_pair(
        struct anyrtc_dtls_transport* const transport,
        struct ice_candpair* const candidate_pair
) {
    struct udp_sock* socket;

    // Check arguments
    if (!transport || !candidate_pair) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // TODO: Implement
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
