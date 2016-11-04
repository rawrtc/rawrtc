#include <sys/types.h>
#include <sys/socket.h> // AF_INET, SOCK_RAW
#include <netinet/in.h> // IPPROTO_UDP
#include <anyrtc.h>
#include "dtls_transport.h"
#include "redirect_transport.h"

#define DEBUG_MODULE "redirect-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Handle incoming messages (that are sent out via the raw socket).
 */
static void receive_handler(
        struct mbuf* const buffer,
        void* const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;

    // TODO: Send over raw socket
}

/*
 * Handle outgoing messages (that came in from the raw socket).
 */
static void send_handler(
        int flags,
        void *const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;

    // TODO: Read from fd

    // Buffer message
    // TODO
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_redirect_transport_destroy(
        void* const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;

    // Remove from DTLS transport
    // Note: No NULL checking needed as the function will do that for us
    anyrtc_dtls_transport_clear_data_transport(transport->dtls_transport);

    // Dereference
    mem_deref(transport->dtls_transport);
}

/*
 * Create a redirect transport.
 */
enum anyrtc_code anyrtc_redirect_transport_create(
        struct anyrtc_redirect_transport** const transportp, // de-referenced
        struct anyrtc_dtls_transport* const dtls_transport, // referenced
        char* const ip, // copied
        uint16_t const port
) {
    bool have_data_transport;
    struct anyrtc_redirect_transport* transport;
    enum anyrtc_code error;

    // Check arguments
    if (!transportp || !dtls_transport || !ip || port == 0) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check DTLS transport state
    if (dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_CLOSED
        || dtls_transport->state == ANYRTC_DTLS_TRANSPORT_STATE_FAILED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Check if a data transport is already registered
    error = anyrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(struct anyrtc_redirect_transport),
                           anyrtc_redirect_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields
    transport->dtls_transport = mem_ref(dtls_transport);
    error = anyrtc_error_to_code(sa_set_str(&transport->address, ip, port));
    if (error) {
        goto out;
    }

    // Create raw socket
    if (socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) {
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // Listen on raw socket
    error = anyrtc_error_to_code(fd_listen(
            transport->socket, FD_READ, send_handler, transport));
    if (error) {
        goto out;
    }

    // Attach to ICE transport
    error = anyrtc_dtls_transport_set_data_transport(dtls_transport, receive_handler, transport);
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}
