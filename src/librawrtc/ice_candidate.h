#pragma once
#include <rawrtc.h>

/*
 * ICE candidate storage type (internal).
 */
enum rawrtc_ice_candidate_storage {
    RAWRTC_ICE_CANDIDATE_STORAGE_RAW,
    RAWRTC_ICE_CANDIDATE_STORAGE_LCAND,
    RAWRTC_ICE_CANDIDATE_STORAGE_RCAND,
};

/*
 * Raw ICE candidate (pending candidate).
 */
struct rawrtc_ice_candidate_raw {
    char* foundation; // copied
    uint32_t priority;
    char* ip; // copied
    enum rawrtc_ice_protocol protocol;
    uint16_t port;
    enum rawrtc_ice_candidate_type type;
    enum rawrtc_ice_tcp_candidate_type tcp_type;
    char* related_address; // copied, nullable
    uint16_t related_port;
};

struct rawrtc_ice_candidate {
    enum rawrtc_ice_candidate_storage storage_type;
    union {
        struct rawrtc_ice_candidate_raw* raw_candidate;
        struct ice_lcand* local_candidate;
        struct ice_rcand* remote_candidate;
    } candidate;
};

// Note: Cannot be public until it uses fixed size types in signature (stdint)
uint32_t rawrtc_ice_candidate_calculate_priority(
    enum ice_cand_type const candidate_type,
    int const protocol,
    int const address_family,
    enum ice_tcptype const tcp_type
);

enum rawrtc_code rawrtc_ice_candidate_create_internal(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    struct pl* const foundation, // copied
    uint32_t const priority,
    struct pl* const ip, // copied
    enum rawrtc_ice_protocol const protocol,
    uint16_t const port,
    enum rawrtc_ice_candidate_type const type,
    enum rawrtc_ice_tcp_candidate_type const tcp_type,
    struct pl* const related_address, // copied, nullable
    uint16_t const related_port
);

enum rawrtc_code rawrtc_ice_candidate_create_from_local_candidate(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_lcand* const local_candidate // referenced
);

enum rawrtc_code rawrtc_ice_candidate_create_from_remote_candidate(
    struct rawrtc_ice_candidate** const candidatep, // de-referenced
    struct ice_rcand* const remote_candidate // referenced
);

int rawrtc_ice_candidate_debug(
    struct re_printf* const pf,
    struct rawrtc_ice_candidate* const candidate
);

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
