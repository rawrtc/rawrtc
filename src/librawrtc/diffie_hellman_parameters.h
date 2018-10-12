#pragma once
#include <rawrtc.h>

enum rawrtc_code rawrtc_set_dh_parameters_der(
        struct tls* const tls,
    uint8_t const* const der,
    size_t const der_size
);

enum rawrtc_code rawrtc_set_dh_parameters_pem(
    struct tls* const tls,
    char const* const pem,
    size_t const pem_size
);

enum rawrtc_code rawrtc_enable_ecdh(
    struct tls* const tls
);
