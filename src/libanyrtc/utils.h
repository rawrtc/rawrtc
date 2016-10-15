#pragma once
#include <anyrtc.h>

enum anyrtc_code anyrtc_translate_re_ice_cand_type(
    enum ice_cand_type re_type,
    enum anyrtc_ice_candidate_type* const typep // de-referenced
);

enum anyrtc_code anyrtc_translate_re_ice_tcptype(
    enum ice_tcptype re_type,
    enum anyrtc_ice_tcp_candidate_type* const typep // de-referenced
);

enum anyrtc_code anyrtc_strdup(
    char** const destination,
    char const * const source
);

enum anyrtc_code anyrtc_snprintf(
    char* const destination,
    size_t const size,
    char* const formatter,
    ...
);

enum anyrtc_code anyrtc_sdprintf(
    char** const destinationp,
    char* const formatter,
    ...
);
