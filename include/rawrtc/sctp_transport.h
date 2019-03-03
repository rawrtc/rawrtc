#pragma once
#include <rawrtcc/code.h>
#include <rawrtcdc/data_channel.h>
#include <rawrtcdc/sctp_transport.h>
#include <re.h>

// Dependencies
struct rawrtc_dtls_transport;

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
);
