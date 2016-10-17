#include <anyrtc.h>
#include "dtls_transport.h"
#include "certificate.h"

#define DEBUG_MODULE "dtls-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

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

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_dtls_transport_destroy(void* arg) {
    struct anyrtc_dtls_transport* transport = arg;

    // Remove from ICE transport
    transport->ice_transport->dtls_transport = NULL;

    // Dereference
    list_flush(&transport->certificates);
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
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;
    struct le* le;

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
        struct anyrtc_certificate* copied_certificate;

        // Copy certificate
        // Note: Copying is needed as the 'le' element cannot be associated to multiple lists
        error = anyrtc_certificate_copy(&copied_certificate, certificates[i]);
        if (error) {
            goto out;
        }

        // Append to list
        list_append(&transport->certificates, &copied_certificate->le, copied_certificate);
    }

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
        list_flush(&transport->certificates);
        mem_deref(transport->ice_transport);
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
