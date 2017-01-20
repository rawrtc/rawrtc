#pragma once
#include <rawrtc.h>

#define RAWRTC_MODULUS_LENGTH_MIN 1024

extern struct rawrtc_config rawrtc_default_config;
extern struct rawrtc_certificate_options rawrtc_default_certificate_options;
extern struct rawrtc_data_channel_options rawrtc_default_data_channel_options;

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

char const * rawrtc_data_transport_type_to_str(
    enum rawrtc_data_transport_type const type
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

extern enum rawrtc_code const rawrtc_ignore_success[];
extern size_t const rawrtc_ignore_success_length;

void rawrtc_before_exit();

void rawrtc_exit_on_error(
    enum rawrtc_code const code,
    enum rawrtc_code const ignore[],
    size_t const n_ignore,
    char const* const file,
    uint32_t const line
);

void rawrtc_exit_on_posix_error(
    int code,
    char const* const file,
    uint32_t line
);

void rawrtc_exit_with_error(
    char const* const file,
    uint32_t line,
    char const* const formatter,
    ...
);

/* Lots of helper macros for the various tools */
#define EOE(code) rawrtc_exit_on_error(code, rawrtc_ignore_success,\
    sizeof(enum rawrtc_code) / sizeof(enum rawrtc_code), __FILE__, __LINE__)
#define EOEIGN(code, ignore) rawrtc_exit_on_error(code, ignore,\
    rawrtc_ignore_success_length, __FILE__, __LINE__)
#define EOR(code) rawrtc_exit_on_posix_error(code, __FILE__, __LINE__)
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || (__GNUC__ >= 3)
#define EWE(...) rawrtc_exit_with_error(__FILE__, __LINE__, __VA_ARGS__)
#elif defined(__GNUC__)
#define EWE(args...) rawrtc_exit_with_error(__FILE__, __LINE__, args)
#endif
