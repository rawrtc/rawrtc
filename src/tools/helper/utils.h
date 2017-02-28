#pragma once
#include <rawrtc.h>
#include "common.h"

/*
 * Convert string to uint16.
 */
bool str_to_uint16(
    uint16_t* const numberp,
    char* const str
);

/*
 * Convert string to uint64.
 */
bool str_to_uint64(
    uint64_t* const numberp,
    char* const str
);

/*
 * Get a dictionary entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_entry(
    void* const valuep,
    struct odict* const parent,
    char* const key,
    enum odict_type const type,
    bool required
);

/*
 * Get a uint32 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint32(
    uint32_t* const valuep,
    struct odict* const parent,
    char* const key,
    bool required
);

/*
 * Get a uint16 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint16(
    uint16_t* const valuep,
    struct odict* const parent,
    char* const key,
    bool required
);

/*
 * Get JSON from stdin and parse it to a dictionary.
 * If no data has been entered, return `true`, otherwise `false`.
 */
bool get_json_stdin(
    struct odict** const dictp // de-referenced
);

/*
 * Get the ICE role from a string.
 */
enum rawrtc_code get_ice_role(
    enum rawrtc_ice_role* const rolep, // de-referenced
    char const* const str
);

/*
 * Create a data channel helper instance.
 */
void data_channel_helper_create(
    struct data_channel_helper** const channel_helperp, // de-referenced
    struct client* const client,
    char* const label
);

/*
 * Create a data channel helper instance from parameters.
 */
void data_channel_helper_create_from_channel(
    struct data_channel_helper** const channel_helperp, // de-referenced
    size_t const size, // zeroable
    struct rawrtc_data_channel* channel,
    struct client* const client
);

/*
 * Add the ICE candidate to the remote ICE transport if the ICE
 * candidate type is enabled.
 */
void add_to_other_if_ice_candidate_type_enabled(
    struct client* const client,
    struct rawrtc_ice_candidate* const candidate,
    struct rawrtc_ice_transport* const transport
);
