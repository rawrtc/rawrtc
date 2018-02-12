#include <rawrtc.h>
#include "sctp_capabilities.h"

/*
 * Local SCTP capabilities.
 */
static struct rawrtc_sctp_capabilities const sctp_capabilities = {
    .max_message_size = RAWRTC_SCTP_CAPABILITIES_MAX_MESSAGE_SIZE
};

/*
 * Print debug information for SCTP capabilities.
 */
int rawrtc_sctp_capabilities_debug(
        struct re_printf* const pf,
        struct rawrtc_sctp_capabilities const* const capabilities
) {
    int err = 0;

    // Check arguments
    if (!capabilities) {
        return 0;
    }

    err |= re_hprintf(pf, "  SCTP Capabilities <%p>:\n", capabilities);

    // Maximum message size
    err |= re_hprintf(pf, "    max_message_size=%"PRIu64"\n", capabilities->max_message_size);

    // Done
    return err;
}

/*
 * Create a new SCTP transport capabilities instance.
 */
enum rawrtc_code rawrtc_sctp_capabilities_create(
        struct rawrtc_sctp_capabilities** const capabilitiesp, // de-referenced
        uint64_t const max_message_size
) {
    struct rawrtc_sctp_capabilities* capabilities;

    // Check arguments
    if (!capabilitiesp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate capabilities
    capabilities = mem_zalloc(sizeof(*capabilities), NULL);
    if (!capabilities) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    capabilities->max_message_size = max_message_size;

    // Set pointer & done
    *capabilitiesp = capabilities;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the SCTP parameter's maximum message size value.
 */
enum rawrtc_code rawrtc_sctp_capabilities_get_max_message_size(
        uint64_t* const max_message_sizep, // de-referenced
        struct rawrtc_sctp_capabilities* const capabilities
) {
    // Check arguments
    if (!capabilities) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    *max_message_sizep = capabilities->max_message_size;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the local SCTP transport capabilities (static).
 */
enum rawrtc_code rawrtc_sctp_transport_get_capabilities(
        struct rawrtc_sctp_capabilities** const capabilitiesp // de-referenced
) {
    return rawrtc_sctp_capabilities_create(capabilitiesp, sctp_capabilities.max_message_size);
}
