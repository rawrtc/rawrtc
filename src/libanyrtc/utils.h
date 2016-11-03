#pragma once
#include <anyrtc.h>

#define ANYRTC_MODULUS_LENGTH_MIN 1024

extern struct anyrtc_config anyrtc_default_config;
extern struct anyrtc_certificate_options anyrtc_default_certificate_options;

enum ice_cand_type anyrtc_ice_candidate_type_to_ice_cand_type(
    enum anyrtc_ice_candidate_type const type
);

enum anyrtc_code anyrtc_ice_cand_type_to_ice_candidate_type(
        enum anyrtc_ice_candidate_type* const typep, // de-referenced
        const enum ice_cand_type re_type
);

enum ice_tcptype anyrtc_ice_tcp_candidate_type_to_ice_tcptype(
        const enum anyrtc_ice_tcp_candidate_type type
);

enum anyrtc_code anyrtc_ice_tcptype_to_ice_tcp_candidate_type(
        enum anyrtc_ice_tcp_candidate_type* const typep, // de-referenced
        const enum ice_tcptype re_type
);

enum trice_role anyrtc_ice_role_to_trice_role(
        enum anyrtc_ice_role const role
);

enum anyrtc_code anyrtc_trice_role_to_ice_role(
        enum anyrtc_ice_role* const rolep, // de-referenced
        enum trice_role const re_role
);

enum tls_keytype anyrtc_certificate_key_type_to_tls_keytype(
        const enum anyrtc_certificate_key_type type
);

enum anyrtc_code anyrtc_tls_keytype_to_certificate_key_type(
        enum anyrtc_certificate_key_type* const typep, // de-referenced
        enum tls_keytype const re_type
);

enum anyrtc_code anyrtc_certificate_sign_algorithm_to_tls_fingerprint(
        enum tls_fingerprint* const fingerprintp, // de-referenced
        enum anyrtc_certificate_sign_algorithm const algorithm
);

enum anyrtc_code anyrtc_tls_fingerprint_to_certificate_sign_algorithm(
        enum anyrtc_certificate_sign_algorithm* const algorithmp, // de-referenced
        enum tls_fingerprint re_algorithm
);

EVP_MD const * const anyrtc_get_sign_function(
    enum anyrtc_certificate_sign_algorithm type
);

enum anyrtc_code anyrtc_get_sign_algorithm_length(
    size_t* const sizep, // de-referenced
    enum anyrtc_certificate_sign_algorithm const type
);
