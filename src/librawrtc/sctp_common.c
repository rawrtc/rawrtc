#include <rawrtc.h>
#include "dtls_transport.h"
#include "sctp_common.h"

// Note: Although shared with the redirect transport, this name is accurate enough for both.
#define DEBUG_MODULE "sctp-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

// TODO: Remove sanity check once https://github.com/NEAT-project/usrsctp-neat/issues/12
//       has been resolved.
pthread_t rawrtc_sctp_common_main_thread;

/*
 * External DTLS role getter.
 * Warning: `rolep` and `arg` will not be validated.
 */
enum rawrtc_code rawrtc_sctp_common_dtls_role_getter(
        enum rawrtc_external_dtls_role* const rolep, // de-referenced, not checked
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    if (pthread_self() != rawrtc_sctp_common_main_thread) {
        DEBUG_WARNING("dtls_role_getter called from different thread: %u\n", pthread_self());
    }
    return rawrtc_dtls_transport_get_external_role(rolep, dtls_transport);
}

/*
 * Get the external DTLS transport state.
 * Warning: `statep` and `arg` will not be validated.
 */
enum rawrtc_code rawrtc_sctp_common_dtls_transport_state_getter(
        enum rawrtc_external_dtls_transport_state* const statep, // de-referenced, not checked
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    if (pthread_self() != rawrtc_sctp_common_main_thread) {
        DEBUG_WARNING("dtls_transport_state_getter called from different thread: %u\n",
                      pthread_self());
    }
    return rawrtc_dtls_transport_get_external_state(statep, dtls_transport);
}

/*
 * Outbound data handler of the SCTP transport.
 * `buffer` will be a fake `mbuf` structure.
 *
 * Warning: `buffer` and `arg` will not be validated.
 */
enum rawrtc_code rawrtc_sctp_common_sctp_transport_outbound_handler(
        struct mbuf* const buffer, // not checked
        uint8_t const tos,
        uint8_t const set_df,
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    enum rawrtc_code error;
    if (pthread_self() != rawrtc_sctp_common_main_thread) {
        DEBUG_WARNING("sctp_transport_outbound_handler called from different thread: %u\n",
                      pthread_self());
    }

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
 * Detach the SCTP transport from the DTLS transport and therefore
 * don't feed any DTLS application data to the SCTP transport.
 * Warning: `arg` will not be validated.
 */
void rawrtc_sctp_common_sctp_transport_detach_handler(
        void* const arg // not checked
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;
    if (pthread_self() != rawrtc_sctp_common_main_thread) {
        DEBUG_WARNING("sctp_transport_detach_handler called from different thread: %u\n",
                      pthread_self());
    }

    // Detach from DTLS transport
    enum rawrtc_code error = rawrtc_dtls_transport_clear_data_transport(dtls_transport);
    if (error) {
        DEBUG_WARNING("Unable to detach from DTLS transport, reason: %s\n",
                      rawrtc_code_to_str(error));
    }
}
