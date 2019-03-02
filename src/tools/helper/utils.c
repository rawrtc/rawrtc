#include <limits.h> // ULONG_MAX
#include <stdlib.h> // strtol
#include <string.h> // strlen
#include <rawrtc.h>
#include "common.h"
#include "utils.h"

#define DEBUG_MODULE "helper-utils"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Convert string to uint16.
 */
bool str_to_uint16(
        uint16_t* const numberp,
        char* const str
) {
    char* end;
    unsigned long number = strtoul(str, &end, 10);

    // Check result (this function is insane, srsly...)
    if (*end != '\0' || (number == ULONG_MAX && errno == ERANGE)) {
        return false;
    }

    // Check bounds
#if (ULONG_MAX > UINT16_MAX)
    if (number > UINT16_MAX) {
        return false;
    }
#endif

    // Done
    *numberp = (uint16_t) number;
    return true;
}

/*
 * Convert string to uint64.
 */
bool str_to_uint64(
        uint64_t* const numberp,
        char* const str
) {
    char* end;
    unsigned long long number = strtoull(str, &end, 10);

    // Check result (this function is insane, srsly...)
    if (*end != '\0' || (number == ULONG_MAX && errno == ERANGE)) {
        return false;
    }

    // Check bounds
#if (ULONG_MAX > UINT64_MAX)
    if (number > UINT64_MAX) {
        return false;
    }
#endif

    // Done
    *numberp = (uint64_t) number;
    return true;
}

/*
 * Get a dictionary entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_entry(
        void* const valuep,
        struct odict* const parent,
        char* const key,
        enum odict_type const type,
        bool required
) {
    struct odict_entry const * entry;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Do lookup
    entry = odict_lookup(parent, key);

    // Check for entry
    if (!entry) {
        if (required) {
            DEBUG_WARNING("'%s' missing\n", key);
            return RAWRTC_CODE_INVALID_ARGUMENT;
        } else {
            return RAWRTC_CODE_NO_VALUE;
        }
    }

    // Check for type
    if (entry->type != type) {
        DEBUG_WARNING("'%s' is of different type than expected\n", key);
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value according to type
    switch (type) {
        case ODICT_OBJECT:
        case ODICT_ARRAY:
            *((struct odict** const) valuep) = entry->u.odict;
            break;
        case ODICT_STRING:
            *((char** const) valuep) = entry->u.str;
            break;
        case ODICT_INT:
            *((int64_t* const) valuep) = entry->u.integer;
            break;
        case ODICT_DOUBLE:
            *((double* const) valuep) = entry->u.dbl;
            break;
        case ODICT_BOOL:
            *((bool* const) valuep) = entry->u.boolean;
            break;
        case ODICT_NULL:
            *((char** const) valuep) = NULL; // meh!
            break;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get a uint32 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint32(
        uint32_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT32_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value & done
    *valuep = (uint32_t) value;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get a uint16 entry and store it in `*valuep`.
 */
enum rawrtc_code dict_get_uint16(
        uint16_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT16_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value & done
    *valuep = (uint16_t) value;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get JSON from stdin and parse it to a dictionary.
 */
enum rawrtc_code get_json_stdin(
        struct odict** const dictp // de-referenced
) {
    char buffer[PARAMETERS_MAX_LENGTH];
    size_t length;

    // Get message from stdin
    if (!fgets((char*) buffer, PARAMETERS_MAX_LENGTH, stdin)) {
        EWE("Error polling stdin");
    }
    length = strlen(buffer);

    // Exit?
    if (length == 1 && buffer[0] == '\n') {
        return RAWRTC_CODE_NO_VALUE;
    }

    // Decode JSON
    EOR(json_decode_odict(dictp, 16, buffer, length, 3));
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the ICE role from a string.
 */
enum rawrtc_code get_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        char const* const str
) {
    // Get ICE role
    switch (str[0]) {
        case '0':
            *rolep = RAWRTC_ICE_ROLE_CONTROLLED;
            return RAWRTC_CODE_SUCCESS;
        case '1':
            *rolep = RAWRTC_ICE_ROLE_CONTROLLING;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}

static void data_channel_helper_destroy(
        void* arg
) {
    struct data_channel_helper* const channel = arg;

    // Unset handler argument & handlers of the channel
    if (channel->channel) {
        EOE(rawrtc_data_channel_unset_handlers(channel->channel));
    }

    // Remove from list
    list_unlink(&channel->le);

    // Un-reference
    mem_deref(channel->arg);
    mem_deref(channel->label);
    mem_deref(channel->channel);
}

/*
 * Create a data channel helper instance.
 */
void data_channel_helper_create(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct client* const client,
        char* const label
) {
    // Allocate
    struct data_channel_helper* const channel =
            mem_zalloc(sizeof(*channel), data_channel_helper_destroy);
    if (!channel) {
        EOE(RAWRTC_CODE_NO_MEMORY);
        return;
    }

    // Set fields
    channel->client = client;
    EOE(rawrtc_strdup(&channel->label, label));

    // Set pointer & done
    *channel_helperp = channel;
}

/*
 * Create a data channel helper instance from parameters.
 */
void data_channel_helper_create_from_channel(
        struct data_channel_helper** const channel_helperp, // de-referenced
        struct rawrtc_data_channel* channel,
        struct client* const client,
        void* const arg // nullable
) {
    enum rawrtc_code error;
    struct rawrtc_data_channel_parameters* parameters;
    char* label;

    // Allocate
    struct data_channel_helper* const channel_helper =
            mem_zalloc(sizeof(*channel_helper), data_channel_helper_destroy);
    if (!channel_helper) {
        EOE(RAWRTC_CODE_NO_MEMORY);
        return;
    }

    // Get parameters
    EOE(rawrtc_data_channel_get_parameters(&parameters, channel));

    // Get & set label
    error = rawrtc_data_channel_parameters_get_label(&label, parameters);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            EOE(rawrtc_strdup(&channel_helper->label, label));
            mem_deref(label);
            break;
        case RAWRTC_CODE_NO_VALUE:
            EOE(rawrtc_strdup(&channel_helper->label, "n/a"));
            break;
        default:
            EOE(error);
    }

    // Set fields
    channel_helper->client = client;
    channel_helper->channel = channel;
    channel_helper->arg = mem_ref(arg);

    // Set pointer
    *channel_helperp = channel_helper;

    // Un-reference & done
    mem_deref(parameters);
}

/*
 * Add the ICE candidate to the remote ICE transport if the ICE
 * candidate type is enabled.
 */
void add_to_other_if_ice_candidate_type_enabled(
        struct client* const client,
        struct rawrtc_ice_candidate* const candidate,
        struct rawrtc_ice_transport* const transport
) {
    if (candidate) {
        enum rawrtc_ice_candidate_type type;

        // Get ICE candidate type
        EOE(rawrtc_ice_candidate_get_type(&type, candidate));

        // Add to other client as remote candidate (if type enabled)
        if (ice_candidate_type_enabled(client, type)) {
            EOE(rawrtc_ice_transport_add_remote_candidate(transport, candidate));
        }
    } else {
        // Last candidate is always being added
        EOE(rawrtc_ice_transport_add_remote_candidate(transport, candidate));
    }
}
