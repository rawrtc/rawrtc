#pragma once
#include <anyrtc.h>

#define ANYRTC_MODULUS_LENGTH_MIN 1024

extern struct anyrtc_config anyrtc_default_config;
extern struct anyrtc_certificate_options anyrtc_default_certificate_options;

enum ice_cand_type anyrtc_translate_ice_candidate_type(
    enum anyrtc_ice_candidate_type type
);

enum anyrtc_code anyrtc_translate_re_ice_cand_type(
    enum anyrtc_ice_candidate_type* const typep, // de-referenced
    enum ice_cand_type re_type
);

enum ice_tcptype anyrtc_translate_ice_tcp_candidate_type(
    enum anyrtc_ice_tcp_candidate_type type
);

enum anyrtc_code anyrtc_translate_re_ice_tcptype(
    enum anyrtc_ice_tcp_candidate_type* const typep, // de-referenced
    enum ice_tcptype re_type
);

enum tls_key_type anyrtc_translate_certificate_key_type(
    enum anyrtc_certificate_key_type type
);

enum anyrtc_code anyrtc_translate_re_tls_key_type(
    enum anyrtc_certificate_key_type* const typep, // de-referenced
    enum tls_key_type const re_type
);

enum anyrtc_code anyrtc_translate_certificate_sign_algorithm(
    enum tls_fingerprint* const fingerprintp, // de-referenced
    enum anyrtc_certificate_sign_algorithm const algorithm
);

enum anyrtc_code anyrtc_translate_re_tls_fingerprint(
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
