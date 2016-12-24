#pragma once
#include <rawrtc.h>

#define RAWRTC_MODULUS_LENGTH_MIN 1024

extern struct rawrtc_config rawrtc_default_config;
extern struct rawrtc_certificate_options rawrtc_default_certificate_options;

enum ice_cand_type rawrtc_ice_candidate_type_to_ice_cand_type(
    enum rawrtc_ice_candidate_type const type
);

enum rawrtc_code rawrtc_ice_cand_type_to_ice_candidate_type(
        enum rawrtc_ice_candidate_type* const typep, // de-referenced
        const enum ice_cand_type re_type
);

enum ice_tcptype rawrtc_ice_tcp_candidate_type_to_ice_tcptype(
        const enum rawrtc_ice_tcp_candidate_type type
);

enum rawrtc_code rawrtc_ice_tcptype_to_ice_tcp_candidate_type(
        enum rawrtc_ice_tcp_candidate_type* const typep, // de-referenced
        const enum ice_tcptype re_type
);

enum trice_role rawrtc_ice_role_to_trice_role(
        enum rawrtc_ice_role const role
);

enum rawrtc_code rawrtc_trice_role_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        enum trice_role const re_role
);

enum tls_keytype rawrtc_certificate_key_type_to_tls_keytype(
        const enum rawrtc_certificate_key_type type
);

enum rawrtc_code rawrtc_tls_keytype_to_certificate_key_type(
        enum rawrtc_certificate_key_type* const typep, // de-referenced
        enum tls_keytype const re_type
);

enum rawrtc_code rawrtc_certificate_sign_algorithm_to_tls_fingerprint(
        enum tls_fingerprint* const fingerprintp, // de-referenced
        enum rawrtc_certificate_sign_algorithm const algorithm
);

enum rawrtc_code rawrtc_tls_fingerprint_to_certificate_sign_algorithm(
        enum rawrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        enum tls_fingerprint re_algorithm
);

EVP_MD const * const rawrtc_get_sign_function(
    enum rawrtc_certificate_sign_algorithm type
);

enum rawrtc_code rawrtc_get_sign_algorithm_length(
    size_t* const sizep, // de-referenced
    enum rawrtc_certificate_sign_algorithm const type
);

enum rawrtc_code rawrtc_bin_to_colon_hex(
    char** const destinationp, // de-referenced
    uint8_t* const source,
    size_t const length
);

enum rawrtc_code rawrtc_colon_hex_to_bin(
    size_t* const bytes_written, // de-referenced
    uint8_t* const buffer, // written into
    size_t const buffer_size,
    char* source
);
