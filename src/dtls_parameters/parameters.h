#pragma once
#include <rawrtc/dtls_fingerprint.h>
#include <rawrtc/dtls_parameters.h>
#include <rawrtc/dtls_transport.h>
#include <rawrtcc/code.h>
#include <re.h>

struct rawrtc_dtls_parameters {
    enum rawrtc_dtls_role role;
    struct rawrtc_dtls_fingerprints* fingerprints;
};

enum rawrtc_code rawrtc_dtls_parameters_create_internal(
    struct rawrtc_dtls_parameters** const parametersp, // de-referenced
    enum rawrtc_dtls_role const role,
    struct list* const fingerprints
);

int rawrtc_dtls_parameters_debug(
    struct re_printf* const pf,
    struct rawrtc_dtls_parameters const* const parameters
);
