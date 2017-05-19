#include <string.h> // memset
#include <sys/types.h>
#include <sys/socket.h> // AF_INET, SOCK_RAW, sendto, recvfrom
#include <netinet/in.h> // IPPROTO_RAW, ntohs, htons
#include <unistd.h> // close
#include <errno.h>
#include <rawrtc_internal.h>
#include "crc32c.h"
#include "dtls_transport.h"
#include "sctp_redirect_transport.h"

#define DEBUG_MODULE "redirect-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Patch local and remote port in the SCTP packet header.
 */
static void patch_sctp_header(
        struct mbuf* const buffer,
        uint16_t const source,
        uint16_t const destination
) {
    size_t const start = buffer->pos;
    int err;
    uint32_t checksum;

    // Patch source port
    err = mbuf_write_u16(buffer, htons(source));
    if (err) {
        DEBUG_WARNING("Could not patch source port, reason: %m\n", err);
        return;
    }

    // Patch destination port
    err = mbuf_write_u16(buffer, htons(destination));
    if (err) {
        DEBUG_WARNING("Could not patch destination port, reason: %m\n", err);
        return;
    }

    // Skip verification tag
    mbuf_advance(buffer, 4);

    // Reset checksum field to '0' and rewind back
    memset(mbuf_buf(buffer), 0, 4);
    mbuf_set_pos(buffer, start);
    // Recalculate checksum
    checksum = crc32c(0, mbuf_buf(buffer), mbuf_get_left(buffer));
    // Advance to checksum field, set it and rewind back
    mbuf_advance(buffer, 8);
    err = mbuf_write_u32(buffer, checksum);
    if (err) {
        DEBUG_WARNING("Could not patch checksum, reason: %m\n", err);
        return;
    }
    mbuf_set_pos(buffer, start);
}

/*
 * Handle outgoing messages (that came in from the raw socket).
 */
static void redirect_from_raw(
        int flags,
        void* arg
) {
    struct rawrtc_sctp_redirect_transport* const transport = arg;
    struct mbuf* buffer;
    enum rawrtc_code error;
    struct sockaddr_in from_address;
    socklen_t address_length;
    ssize_t length;
    struct sa from;
    size_t header_length;
    uint16_t source;
    uint16_t destination;

    if ((flags & FD_READ) == FD_READ) {
        buffer = transport->buffer;

        // Rewind buffer
        mbuf_rewind(buffer);

        // Receive
        address_length = sizeof(from_address);
        length = recvfrom(transport->socket, mbuf_buf(buffer), mbuf_get_space(buffer),
                0, (struct sockaddr*) &from_address, &address_length);
        if (length == -1) {
            DEBUG_WARNING("Unable to receive raw message: %m\n", errno);
            return;
        }
        mbuf_set_end(buffer, (size_t) length);

        // TODO: Receive remaining bytes (if any)

        // Check address
        error = rawrtc_error_to_code(sa_set_sa(&from, (struct sockaddr*) &from_address));
        if (error) {
            DEBUG_WARNING("Invalid sender address: %m\n", error);
            return;
        }
        DEBUG_PRINTF("Received %zu bytes via RAW from %j\n", mbuf_get_left(buffer), &from);
        if (!sa_isset(&from, SA_ADDR) && !sa_cmp(&transport->redirect_address, &from, SA_ADDR)) {
            DEBUG_WARNING("Ignoring data from unknown address");
            return;
        }

        // Skip IPv4 header
        header_length = (size_t) (mbuf_read_u8(buffer) & 0xf);
        mbuf_advance(buffer, -1);
        DEBUG_PRINTF("RAW IPv4 header length: %zu\n", header_length);
        mbuf_advance(buffer, header_length * 4);

        // Read source and destination port
        source = ntohs(mbuf_read_u16(buffer));
        destination = ntohs(mbuf_read_u16(buffer));
        sa_set_port(&from, source);
        (void) destination;
        DEBUG_PRINTF("RAW from %J to %"PRIu16"\n", &from, destination);
        mbuf_advance(buffer, -4);

        // Is this from the correct source?
        if (source != sa_port(&transport->redirect_address)) {
            DEBUG_WARNING("Ignored data from different source\n");
            return;
        }

        // Update SCTP header with changed ports
        patch_sctp_header(buffer, transport->local_port, transport->remote_port);

        // Send data
        error = rawrtc_dtls_transport_send(transport->dtls_transport, buffer);
        if (error) {
            DEBUG_WARNING("Could not send, error: %m\n", error);
            return;
        }
    }
}

/*
 * Handle incoming messages (that are sent out via the raw socket).
 */
static void redirect_to_raw(
        struct mbuf* const buffer,
        void* const arg
) {
    struct rawrtc_sctp_redirect_transport* const transport = arg;
    ssize_t length;

    // Check state
    if (transport->state != RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_OPEN) {
        DEBUG_NOTICE("Ignored packet of %zu bytes as transport is not open\n",
                     mbuf_get_left(buffer));
        return;
    }

    // Update SCTP header with changed ports
    patch_sctp_header(buffer, transport->local_port, sa_port(&transport->redirect_address));

    // Send over raw socket
    DEBUG_PRINTF("Redirecting message (%zu bytes) to %J\n",
            mbuf_get_left(buffer), &transport->redirect_address);
    length = sendto(transport->socket, mbuf_buf(buffer), mbuf_get_left(buffer), 0,
            &transport->redirect_address.u.sa, transport->redirect_address.len);
    if (length == -1) {
        DEBUG_WARNING("Unable to redirect message: %m\n", errno);
        return;
    }
    mbuf_advance(buffer, length);
}

/*
 * Change the state of the SCTP redirect transport.
 * Caller MUST ensure that the same state is not set twice.
 */
static void set_state(
        struct rawrtc_sctp_redirect_transport* const transport, // not checked
        enum rawrtc_sctp_redirect_transport_state const state
) {
    // Closed?
    if (state == RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_CLOSED) {
        // Stop listening and close raw socket
        if (transport->socket != -1) {
            fd_close(transport->socket);
            if (close(transport->socket)) {
                DEBUG_WARNING("Closing raw socket failed: %m\n", errno);
            }
        }

        // Remove from DTLS transport
        // Note: No NULL checking needed as the function will do that for us
        rawrtc_dtls_transport_clear_data_transport(transport->dtls_transport);
    }

    // Set state
    transport->state = state;

    // TODO: Raise event
}

/*
 * Destructor for an existing SCTP redirect transport.
 */
static void rawrtc_sctp_redirect_transport_destroy(
        void* arg
) {
    struct rawrtc_sctp_redirect_transport* const transport = arg;

    // Stop transport
    rawrtc_sctp_redirect_transport_stop(transport);

    // Un-reference
    mem_deref(transport->dtls_transport);
    mem_deref(transport->buffer);
}

/*
 * Create an SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_create(
        struct rawrtc_sctp_redirect_transport** const transportp, // de-referenced
        struct rawrtc_dtls_transport* const dtls_transport, // referenced
        uint16_t const port, // zeroable
        char* const redirect_ip, // copied
        uint16_t const redirect_port
) {
    bool have_data_transport;
    struct rawrtc_sctp_redirect_transport* transport;
    enum rawrtc_code error;

    // Check arguments
    if (!transportp || !dtls_transport || !redirect_ip || redirect_port == 0) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check DTLS transport state
    if (dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_CLOSED
        || dtls_transport->state == RAWRTC_DTLS_TRANSPORT_STATE_FAILED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Check if a data transport is already registered
    error = rawrtc_dtls_transport_have_data_transport(&have_data_transport, dtls_transport);
    if (error) {
        return error;
    }
    if (have_data_transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), rawrtc_sctp_redirect_transport_destroy);
    if (!transport) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    transport->state = RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_NEW;
    transport->dtls_transport = mem_ref(dtls_transport);
    transport->local_port = port ? port : RAWRTC_SCTP_REDIRECT_TRANSPORT_DEFAULT_PORT;
    error = rawrtc_error_to_code(sa_set_str(
            &transport->redirect_address, redirect_ip, redirect_port));
    if (error) {
        goto out;
    }

    // Create buffer
    transport->buffer = mbuf_alloc(2048);
    if (!transport->buffer) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Create raw socket
    transport->socket = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
    if (transport->socket == -1) {
        error = rawrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Set non-blocking

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

/*
 * Start an SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_start(
        struct rawrtc_sctp_redirect_transport* const transport,
        struct rawrtc_sctp_capabilities const * const remote_capabilities, // copied
        uint16_t remote_port // zeroable
) {
    enum rawrtc_code error;

    // Check arguments
    if (!transport || !remote_capabilities) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state != RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_NEW) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Set default port (if 0)
    if (remote_port == 0) {
        remote_port = transport->local_port;
    }

    // Store remote port
    transport->remote_port = remote_port;

    // Listen on raw socket
    error = rawrtc_error_to_code(fd_listen(
            transport->socket, FD_READ, redirect_from_raw, transport));
    if (error) {
        goto out;
    }

    // Attach to ICE transport
    error = rawrtc_dtls_transport_set_data_transport(
            transport->dtls_transport, redirect_to_raw, transport);
    if (error) {
        goto out;
    }

    // Update state & done
    set_state(transport, RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_OPEN);
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        // Stop listening on raw socket
        fd_close(transport->socket);
    }
    return error;
}

/*
 * Stop and close the SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_stop(
        struct rawrtc_sctp_redirect_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (transport->state == RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Update state
    set_state(transport, RAWRTC_SCTP_REDIRECT_TRANSPORT_STATE_CLOSED);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the redirected local SCTP port of the SCTP redirect transport.
 */
enum rawrtc_code rawrtc_sctp_redirect_transport_get_port(
        uint16_t* const portp, // de-referenced
        struct rawrtc_sctp_redirect_transport* const transport
) {
    // Check arguments
    if (!portp || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set port
    *portp = transport->local_port;

    // Done
    return RAWRTC_CODE_SUCCESS;
}
