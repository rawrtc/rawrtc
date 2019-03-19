#pragma once
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE gather policy.
 */
enum rawrtc_ice_gather_policy {
    RAWRTC_ICE_GATHER_POLICY_ALL,
    RAWRTC_ICE_GATHER_POLICY_NOHOST,
    RAWRTC_ICE_GATHER_POLICY_RELAY,
};

/*
 * ICE credential type
 */
enum rawrtc_ice_credential_type {
    RAWRTC_ICE_CREDENTIAL_TYPE_NONE,
    RAWRTC_ICE_CREDENTIAL_TYPE_PASSWORD,
    RAWRTC_ICE_CREDENTIAL_TYPE_TOKEN,
};

/*
 * ICE gather options.
 */
struct rawrtc_ice_gather_options;

/*
 * Create a new ICE gather options instance.
 * `*optionsp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gather_options_create(
    struct rawrtc_ice_gather_options** const optionsp,  // de-referenced
    enum rawrtc_ice_gather_policy const gather_policy);

/*
 * Add an ICE server to the gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_add_server(
    struct rawrtc_ice_gather_options* const options,
    char* const* const urls,  // copied
    size_t const n_urls,
    char* const username,  // nullable, copied
    char* const credential,  // nullable, copied
    enum rawrtc_ice_credential_type const credential_type);

/*
 * Translate an ICE gather policy to str.
 */
char const* rawrtc_ice_gather_policy_to_str(enum rawrtc_ice_gather_policy const policy);

/*
 * Translate a str to an ICE gather policy (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_gather_policy(
    enum rawrtc_ice_gather_policy* const policyp,  // de-referenced
    char const* const str);
