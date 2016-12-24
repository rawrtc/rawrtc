#include <rawrtc.h>
#include "data_transport.h"

#define DEBUG_MODULE "data-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Destructor for an existing data transport.
 */
static void rawrtc_sctp_transport_destroy(
        void* const arg
) {
    struct rawrtc_data_transport* const transport = arg;

    // Dereference
    mem_deref(transport->transport);
}

/*
 * Create a data transport instance.
 */
enum rawrtc_code rawrtc_data_transport_create(
        struct rawrtc_data_transport** const transportp, // de-referenced
        enum rawrtc_data_transport_type const type,
        void* const internal_transport, // referenced
        rawrtc_data_transport_channel_create_handler* const channel_create_handler,
        rawrtc_data_transport_channel_close_handler* const channel_close_handler,
        rawrtc_data_transport_channel_send_handler* const channel_send_handler
) {
    struct rawrtc_data_transport* transport;

    // Check arguments
    if (!transportp || !internal_transport || !channel_create_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), rawrtc_sctp_transport_destroy);
    if (!transport) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    transport->type = type;
    transport->transport = mem_ref(internal_transport);
    transport->channel_create = channel_create_handler;
    transport->channel_close = channel_close_handler;
    transport->channel_send = channel_send_handler;

    // Set pointer & done
    *transportp = transport;
    return RAWRTC_CODE_SUCCESS;
}
