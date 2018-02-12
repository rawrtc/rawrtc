#pragma once

enum {
    RAWRTC_SCTP_CAPABILITIES_MAX_MESSAGE_SIZE = 0,
};

int rawrtc_sctp_capabilities_debug(
    struct re_printf* const pf,
    struct rawrtc_sctp_capabilities const* const capabilities
);
