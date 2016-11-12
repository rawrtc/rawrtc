#include <string.h> // memset
#include <sys/types.h>
#include <sys/socket.h> // AF_INET, SOCK_RAW, sendto, recvfrom
#include <netinet/in.h> // IPPROTO_RAW, ntohs, htons
#include <unistd.h> // close
#include <errno.h>
#include <anyrtc.h>
#include "crc32c.h"
#include "dtls_transport.h"
#include "redirect_transport.h"

#define DEBUG_MODULE "redirect-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

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
        void *const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;
    struct mbuf* buffer;
    enum anyrtc_code error;
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
        address_length = sizeof(struct sockaddr_in);
        length = recvfrom(transport->socket, mbuf_buf(buffer), mbuf_get_space(buffer),
                0, (struct sockaddr*) &from_address, &address_length);
        if (length == -1) {
            DEBUG_WARNING("Unable to receive raw message: %m\n", errno);
            return;
        }
        mbuf_set_end(buffer, (size_t) length);

        // TODO: Receive remaining bytes (if any)

        // Check address
        error = anyrtc_error_to_code(sa_set_sa(&from, (struct sockaddr*) &from_address));
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
        header_length = (mbuf_read_u8(buffer) & 0xf);
        mbuf_advance(buffer, -1);
        DEBUG_PRINTF("RAW IPv4 header length: %zu\n", header_length);
        mbuf_advance(buffer, header_length * 4);

        // Read source and destination port
        source = ntohs(mbuf_read_u16(buffer));
        destination = ntohs(mbuf_read_u16(buffer));
        sa_set_port(&from, source);
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
        error = anyrtc_dtls_transport_send(transport->dtls_transport, buffer);
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
    struct anyrtc_redirect_transport* const transport = arg;
    ssize_t length;

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
 * Destructor for an existing ICE transport.
 */
static void anyrtc_redirect_transport_destroy(
        void* const arg
) {
    struct anyrtc_redirect_transport* const transport = arg;

    // Stop listening and close raw socket
    fd_close(transport->socket);
    if (close(transport->socket)) {
        DEBUG_WARNING("Closing raw socket failed: %m\n", errno);
    }

    // Remove from DTLS transport
    // Note: No NULL checking needed as the function will do that for us
    anyrtc_dtls_transport_clear_data_transport(transport->dtls_transport);

    // Dereference
    mem_deref(transport->dtls_transport);
    mem_deref(transport->buffer);
}

/*
 * Create a redirect transport.
 * `local_port` and `remote_port` may be `0`.
 * TODO: local and remote port should probably be in SCTPCapabilities? Open issue for ORTC spec.
 */
enum anyrtc_code anyrtc_redirect_transport_create(
        struct anyrtc_redirect_transport** const transportp, // de-referenced
        struct anyrtc_dtls_transport* const dtls_transport, // referenced
        char* const redirect_ip, // copied
        uint16_t const redirect_port,
        uint16_t const local_port, // zeroable
        uint16_t const remote_port // zeroable
) {
    bool have_data_transport;
    struct anyrtc_redirect_transport* transport;
    enum anyrtc_code error;

    // Check arguments
    if (!transportp || !dtls_transport || !redirect_ip || redirect_port == 0) {
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
    transport->local_port = local_port ? local_port : ANYRTC_REDIRECT_TRANSPORT_DEFAULT_PORT;
    transport->remote_port = remote_port ? remote_port : ANYRTC_REDIRECT_TRANSPORT_DEFAULT_PORT;
    error = anyrtc_error_to_code(sa_set_str(
            &transport->redirect_address, redirect_ip, redirect_port));
    if (error) {
        goto out;
    }

    // Create buffer
    transport->buffer = mbuf_alloc(2048);
    if (!transport->buffer) {
        error = ANYRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Create raw socket
    transport->socket = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP);
    if (transport->socket == -1) {
        error = anyrtc_error_to_code(errno);
        goto out;
    }

    // TODO: Set non-blocking

    // Listen on raw socket
    error = anyrtc_error_to_code(fd_listen(
            transport->socket, FD_READ, redirect_from_raw, transport));
    if (error) {
        goto out;
    }

    // Attach to ICE transport
    error = anyrtc_dtls_transport_set_data_transport(
            dtls_transport, redirect_to_raw, transport);
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
