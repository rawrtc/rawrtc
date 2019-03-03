#include <rawrtc.h>
#include "dtls_transport.h"
#include "sctp_common.h"
#include "sctp_redirect_transport.h"

#define DEBUG_MODULE "sctp-redirect-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * Pass DTLS application data to the SCTP redirect transport as inbound
 * data.
 */
static void sctp_redirect_transport_inbound_handler(
        struct mbuf* const buffer, // not checked
        void* const arg // not checked
) {
    struct rawrtc_sctp_redirect_transport* const transport = arg;

    // Feed data
    enum rawrtc_code const error = rawrtc_sctp_redirect_transport_feed_inbound(transport, buffer);
    if (error) {
        DEBUG_WARNING("Unable to feed data into the SCTP redirect transport, reason: %s\n",
                      rawrtc_code_to_str(error));
    }
}

/*
 * Destructor for an existing SCTP redirect transport.
 */
static void rawrtc_sctp_redirect_transport_destroy(
        void* const arg
) {
    struct rawrtc_dtls_transport* const dtls_transport = arg;

    // Un-reference
    mem_deref(dtls_transport);
}

/*
 * Create an SCTP redirect transport.
 * `*transportp` must be unreferenced.
 *
 * `port` defaults to `5000` if set to `0`.
 * `redirect_ip` is the target IP SCTP packets will be redirected to
 *  and must be a IPv4 address.
 * `redirect_port` is the target SCTP port packets will be redirected
 *  to.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_create(
        struct rawrtc_sctp_redirect_transport** const transportp, // de-referenced
        struct rawrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t const port, // zeroable
        char* const redirect_ip, // copied
        uint16_t const redirect_port,
        rawrtc_sctp_redirect_transport_state_change_handler const state_change_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    bool have_data_transport;
    struct rawrtc_sctp_redirect_transport* transport = NULL;

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
        .role_getter = NULL,
        .state_getter = rawrtc_sctp_common_dtls_transport_state_getter,
        .outbound_handler = rawrtc_sctp_common_sctp_transport_outbound_handler,
        .detach_handler = rawrtc_sctp_common_sctp_transport_detach_handler,
        .destroyed_handler = rawrtc_sctp_redirect_transport_destroy,
        .arg = mem_ref(dtls_transport),
    };

    // Create SCTP redirect transport
    error = rawrtc_sctp_redirect_transport_create_from_external(
            &transport, &context, port, redirect_ip, redirect_port, state_change_handler, arg);
    if (error) {
        goto out;
    }

    // Attach to DTLS transport
    DEBUG_PRINTF("Attaching as data transport\n");
    error = rawrtc_dtls_transport_set_data_transport(
            dtls_transport, sctp_redirect_transport_inbound_handler, transport);
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
