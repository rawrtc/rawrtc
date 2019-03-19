#include "address.h"
#include "server.h"
#include <rawrtcc/code.h>
#include <re.h>

/*
 * Destructor for an ICE server URL address.
 */
static void rawrtc_ice_server_url_address_destroy(void* arg) {
    struct rawrtc_ice_server_url_address* const address = arg;

    // Remove from list
    list_unlink(&address->le);

    // Un-reference
    mem_deref(address->url);
}

/*
 * Create an ICE server URL address.
 */
enum rawrtc_code rawrtc_ice_server_url_address_create(
    struct rawrtc_ice_server_url_address** const addressp,  // de-referenced
    struct rawrtc_ice_server_url* const url,  // referenced
    struct sa* const address  // copied
) {
    struct rawrtc_ice_server_url_address* url_address;

    // Check arguments
    if (!addressp || !url || !address) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    url_address = mem_zalloc(sizeof(*url_address), rawrtc_ice_server_url_address_destroy);
    if (!url_address) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    url_address->url = mem_ref(url);
    url_address->address = *address;

    // Set pointer & done
    *addressp = url_address;
    return RAWRTC_CODE_SUCCESS;
}
