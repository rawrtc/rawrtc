#include <anyrtc.h>
#include "data_transport.h"

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
        enum anyrtc_data_transport_type type,
        void* const internal_transport // referenced
) {
    struct anyrtc_data_transport* transport;

    // Check arguments
    if (!transportp || !internal_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), NULL);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    transport->type = type;
    transport->transport = mem_ref(internal_transport);

    // Set pointer & done
    *transportp = transport;
    return ANYRTC_CODE_SUCCESS;
}
