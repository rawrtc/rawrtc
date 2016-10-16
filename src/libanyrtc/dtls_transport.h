#pragma once

enum anyrtc_code anyrtc_dtls_transport_add_candidate_pair(
    struct anyrtc_dtls_transport *const transport,
    struct ice_candpair *const candidate_pair
);
