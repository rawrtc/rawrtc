#include "../dtls_transport/transport.h"
#include "../sctp_common/common.h"
#include <rawrtc/config.h>
#include <rawrtc/dtls_transport.h>
#include <rawrtc/sctp_transport.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <rawrtcdc/data_channel.h>
#include <rawrtcdc/external.h>
#include <rawrtcdc/sctp_transport.h>
#include <re.h>

#define DEBUG_MODULE "sctp-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * Pass DTLS application data to the SCTP transport as inbound data.
 */
static void sctp_transport_inbound_handler(
        struct mbuf* const buffer, // not checked
        void* const arg // not checked
) {
    struct rawrtc_sctp_transport* const transport = arg;

    // Feed data
    // TODO: What about ECN bits?
    enum rawrtc_code const error = rawrtc_sctp_transport_feed_inbound(transport, buffer, 0x00);
    if (error) {
        DEBUG_WARNING("Unable to feed data into the SCTP transport, reason: %s\n",
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
        rawrtc_data_channel_handler const data_channel_handler, // nullable
        rawrtc_sctp_transport_state_change_handler const state_change_handler, // nullable
        void* const arg // nullable
) {
    enum rawrtc_code error;
    bool have_data_transport;
    struct rawrtc_sctp_transport* transport = NULL;

    // Create SCTP transport context
    struct rawrtc_sctp_transport_context context = {
        .role_getter = rawrtc_sctp_common_dtls_role_getter,
        .state_getter = rawrtc_sctp_common_dtls_transport_state_getter,
        .outbound_handler = rawrtc_sctp_common_sctp_transport_outbound_handler,
        .detach_handler = rawrtc_sctp_common_sctp_transport_detach_handler,
        .destroyed_handler = rawrtc_sctp_transport_destroy,
        .trace_packets = false, // TODO: Make this configurable
        .arg = mem_ref(dtls_transport),
    };

    // Check if a data transport is already registered
    error = rawrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        goto out;
    }
    if (have_data_transport) {
        error = RAWRTC_CODE_INVALID_ARGUMENT;
        goto out;
    }

    // Create SCTP transport
    error = rawrtc_sctp_transport_create_from_external(
            &transport, &context, port, data_channel_handler, state_change_handler, arg);
    if (error) {
        goto out;
    }

    // TODO: Set MTU (1200|1280 (IPv4|IPv6) - UDP - DTLS (cipher suite dependent) - SCTP (12)

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
