#include <rawrtc.h>
#include "dtls_transport.h"
#include "sctp_transport.h"

#define DEBUG_MODULE "sctp-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

/*
 * External DTLS role getter.
 */
static enum rawrtc_code dtls_role_getter(
        enum rawrtc_external_dtls_role* const rolep, // de-referenced, not checked
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    return rawrtc_dtls_transport_get_external_role(rolep, dtls_transport);
}

/*
 * Get the external DTLS transport state.
 */
static enum rawrtc_code dtls_transport_state_getter(
        enum rawrtc_external_dtls_transport_state* const statep, // de-referenced, not checked
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    return rawrtc_dtls_transport_get_external_state(statep, dtls_transport);
}

/*
 * Outbound data handler of the SCTP transport.
 * `buffer` will be a fake `mbuf` structure.
 */
enum rawrtc_code sctp_transport_outbound_handler(
        struct mbuf* const buffer,
        uint8_t const tos,
        uint8_t const set_df,
        void* const arg
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    enum rawrtc_code error;

    // TODO: Handle
    (void) tos; (void) set_df;

    // Note: We only need to copy the buffer if we add it to the outgoing queue
    if (dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CONNECTED) {
        // Send
        error = rawrtc_dtls_transport_send(dtls_transport, buffer);
    } else {
        int err;
        struct mbuf* copied_buffer;

        // Get length
        size_t const length = mbuf_get_left(buffer);

        // Allocate
        copied_buffer = mbuf_alloc(length);
        if (!copied_buffer) {
            DEBUG_WARNING("Could not create buffer for outgoing packet, no memory\n");
            return RAWRTC_CODE_NO_MEMORY;
        }

        // Copy and set position
        err = mbuf_write_mem(copied_buffer, mbuf_buf(buffer), length);
        if (err) {
            DEBUG_WARNING("Could not write to buffer, reason: %m\n", err);
            mem_deref(copied_buffer);
            return rawrtc_error_to_code(err);
        }
        mbuf_set_pos(copied_buffer, 0);

        // Send (well, actually buffer...)
        error = rawrtc_dtls_transport_send(dtls_transport, copied_buffer);
        mem_deref(copied_buffer);
    }

    // Handle error & done
    if (error) {
        DEBUG_WARNING("Could not send packet, reason: %s\n", rawrtc_code_to_str(error));
    }
    return error;
}

/*
 * Pass DTLS application data to the SCTP transport as inbound data.
 */
static void sctp_transport_inbound_handler(
        struct mbuf* const buffer,
        void* const arg
) {
    struct rawrtc_sctp_transport* const transport = arg;

    // Feed data
    // TODO: What about ECN bits?
    enum rawrtc_code const error = rawrtc_sctp_transport_feed_inbound(transport, buffer, 0);
    if (error) {
        DEBUG_WARNING("Unable to feed data into the SCTP transport, reason: %s\n",
                      rawrtc_code_to_str(error));
    }
}

/*
 * Detach the SCTP transport from the DTLS transport and therefore
 * don't feed any DTLS application data to the SCTP transport.
 */
static void sctp_transport_detach_handler(
        void* const arg
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;

    // Detach from DTLS transport
    enum rawrtc_code error = rawrtc_dtls_transport_clear_data_transport(dtls_transport);
    if (error) {
        DEBUG_WARNING("Unable to detach from DTLS transport, reason: %s\n",
                      rawrtc_code_to_str(error));
    }
}

/*
 * Destructor for an existing SCTP transport.
 */
static void rawrtc_sctp_transport_destroy(
        void* const arg
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;

    // Un-reference
    mem_deref(dtls_transport);
}

/*
 * Create an SCTP transport.
 * `*transportp` must be unreferenced.
 */
enum rawrtc_code rawrtc_sctp_transport_create(
        struct rawrtc_sctp_transport** const transportp, // de-referenced
        struct rawrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t const port, // zeroable
        rawrtc_data_channel_handler* const data_channel_handler, // nullable
        rawrtc_sctp_transport_state_change_handler* const state_change_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    bool have_data_transport;
    struct rawrtc_sctp_transport* transport;

    // Check if a data transport is already registered
    error = rawrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Create SCTP transport context
    struct rawrtc_sctp_transport_context context = {
        .role_getter = dtls_role_getter,
        .state_getter = dtls_transport_state_getter,
        .outbound_handler = sctp_transport_outbound_handler,
        .detach_handler = sctp_transport_detach_handler,
        .destroyed_handler = rawrtc_sctp_transport_destroy,
        .arg = mem_ref(dtls_transport),
    };

    // Create SCTP transport
    error = rawrtc_sctp_transport_create_from_external(
            &transport, &context, port, data_channel_handler, state_change_handler, arg);
    if (error) {
        goto out;
    }

    // Attach to DTLS transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = rawrtc_dtls_transport_set_data_transport(
            dtls_transport, sctp_transport_inbound_handler, transport);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(transport);
        mem_deref(dtls_transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}
