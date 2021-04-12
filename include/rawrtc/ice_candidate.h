#pragma once
#include <rawrtcc/code.h>
#include <re.h>
#include <netinet/in.h>  // IPPROTO_UDP, IPPROTO_TCP

/*
 * ICE protocol.
 */
enum rawrtc_ice_protocol {
    RAWRTC_ICE_PROTOCOL_UDP = IPPROTO_UDP,
    RAWRTC_ICE_PROTOCOL_TCP = IPPROTO_TCP,
};

/*
 * ICE candidate type.
 */
enum rawrtc_ice_candidate_type {
    RAWRTC_ICE_CANDIDATE_TYPE_HOST = ICE_CAND_TYPE_HOST,
    RAWRTC_ICE_CANDIDATE_TYPE_SRFLX = ICE_CAND_TYPE_SRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_PRFLX = ICE_CAND_TYPE_PRFLX,
    RAWRTC_ICE_CANDIDATE_TYPE_RELAY = ICE_CAND_TYPE_RELAY,
};

/*
 * ICE TCP candidate type.
 */
enum rawrtc_ice_tcp_candidate_type {
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE = ICE_TCP_ACTIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_PASSIVE = ICE_TCP_PASSIVE,
    RAWRTC_ICE_TCP_CANDIDATE_TYPE_SO = ICE_TCP_SO,
};

/*
 * ICE candidate.
 */
struct rawrtc_ice_candidate;

/*
 * ICE candidates.
 * Note: Inherits `struct rawrtc_array_container`.
 */
struct rawrtc_ice_candidates {
    size_t n_candidates;
    struct rawrtc_ice_candidate* candidates[];
};

/*
 * Create an ICE candidate.
 * `*candidatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_create(
    struct rawrtc_ice_candidate** const candidatep,  // de-referenced
    char* const foundation,  // copied
    uint32_t const priority,
    char* const ip,  // copied
    enum rawrtc_ice_protocol const protocol,
    uint16_t const port,
    enum rawrtc_ice_candidate_type const type,
    enum rawrtc_ice_tcp_candidate_type const tcp_type,
    char* const related_address,  // copied, nullable
    uint16_t const related_port);

/*
 * Get the ICE candidate's foundation.
 * `*foundationp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_foundation(
    char** const foundationp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's priority.
 */
enum rawrtc_code rawrtc_ice_candidate_get_priority(
    uint32_t* const priorityp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Check if the ICE candidate contains an mDNS address.
 */
enum rawrtc_code rawrtc_ice_candidate_is_mdns_hostname(
    bool* const is_mdnsp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's IP address.
 * `*ipp` will be set to a copy of the IP address that must be
 * unreferenced.
 */
enum rawrtc_code rawrtc_ice_candidate_get_ip(
    char** const ipp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's protocol.
 */
enum rawrtc_code rawrtc_ice_candidate_get_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's port.
 */
enum rawrtc_code rawrtc_ice_candidate_get_port(
    uint16_t* const portp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's type.
 */
enum rawrtc_code rawrtc_ice_candidate_get_type(
    enum rawrtc_ice_candidate_type* typep,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's TCP type.
 * Return `RAWRTC_CODE_NO_VALUE` in case the protocol is not TCP.
 */
enum rawrtc_code rawrtc_ice_candidate_get_tcp_type(
    enum rawrtc_ice_tcp_candidate_type* typep,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's related IP address.
 * `*related_address` will be set to a copy of the related address that
 * must be unreferenced.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related address exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_address(
    char** const related_addressp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Get the ICE candidate's related IP address' port.
 * `*related_portp` will be set to a copy of the related address'
 * port.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no related port exists.
 */
enum rawrtc_code rawrtc_ice_candidate_get_related_port(
    uint16_t* const related_portp,  // de-referenced
    struct rawrtc_ice_candidate* const candidate);

/*
 * Translate a protocol to the corresponding IPPROTO_*.
 */
int rawrtc_ice_protocol_to_ipproto(enum rawrtc_ice_protocol const protocol);

/*
 * Translate a IPPROTO_* to the corresponding protocol.
 */
enum rawrtc_code rawrtc_ipproto_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    int const ipproto);

/*
 * Translate an ICE protocol to str.
 */
char const* rawrtc_ice_protocol_to_str(enum rawrtc_ice_protocol const protocol);

/*
 * Translate a pl to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    struct pl const* const pl);

/*
 * Translate a str to an ICE protocol (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_protocol(
    enum rawrtc_ice_protocol* const protocolp,  // de-referenced
    char const* const str);

/*
 * Translate an ICE candidate type to str.
 */
char const* rawrtc_ice_candidate_type_to_str(enum rawrtc_ice_candidate_type const type);

/*
 * Translate a pl to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep,  // de-referenced
    struct pl const* const pl);

/*
 * Translate a str to an ICE candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_candidate_type(
    enum rawrtc_ice_candidate_type* const typep,  // de-referenced
    char const* const str);

/*
 * Translate an ICE TCP candidate type to str.
 */
char const* rawrtc_ice_tcp_candidate_type_to_str(enum rawrtc_ice_tcp_candidate_type const type);

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_pl_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep,  // de-referenced
    struct pl const* const pl);

/*
 * Translate a str to an ICE TCP candidate type (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_tcp_candidate_type(
    enum rawrtc_ice_tcp_candidate_type* const typep,  // de-referenced
    char const* const str);
