#pragma once
#include <rawrtcc/code.h>
#include <rawrtcdc/sctp_redirect_transport.h>
#include <re.h>

// Dependencies
struct rawrtc_dtls_transport;

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
);
