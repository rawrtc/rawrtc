#include <anyrtc.h>
#include "data_transport.h"

#define DEBUG_MODULE "data-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Destructor for an existing data transport.
 */
static void anyrtc_sctp_transport_destroy(
        void* const arg
) {
    struct anyrtc_data_transport* const transport = arg;

    // Dereference
    mem_deref(transport->transport);
}

/*
 * Create a data transport instance.
 */
enum anyrtc_code anyrtc_data_transport_create(
        struct anyrtc_data_transport** const transportp, // de-referenced
        enum anyrtc_data_transport_type const type,
        void* const internal_transport, // referenced
        anyrtc_data_transport_channel_create_handler* const channel_create_handler,
        anyrtc_data_transport_channel_close_handler* const channel_close_handler,
        anyrtc_data_transport_channel_send_handler* const channel_send_handler
) {
    struct anyrtc_data_transport* transport;

    // Check arguments
    if (!transportp || !internal_transport || !channel_create_handler) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), anyrtc_sctp_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    transport->type = type;
    transport->transport = mem_ref(internal_transport);
    transport->channel_create = channel_create_handler;
    transport->channel_close = channel_close_handler;
    transport->channel_send = channel_send_handler;

    // Set pointer & done
    *transportp = transport;
    return ANYRTC_CODE_SUCCESS;
}
