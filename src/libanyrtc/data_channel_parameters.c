#include <anyrtc.h>
#include "data_channel_parameters.h"

#define DEBUG_MODULE "data-channel-parameters"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Destructor for existing data channel parameters.
 */
static void anyrtc_data_channel_parameters_destroy(
        void* const arg
) {
    struct anyrtc_data_channel_parameters* const parameters = arg;

    // Dereference
    mem_deref(parameters->label);
    mem_deref(parameters->protocol);
}

/*
 * Create data channel parameters.
 *
 * For `ANYRTC_DATA_CHANNEL_TYPE_RELIABLE_*`, the reliability parameter
 * is being ignored.
 *
 * When using `ANYRTC_DATA_CHANNEL_TYPE_*_RETRANSMIT`, the reliability
 * parameter specifies the number of times a retransmission occurs if
 * not acknowledged before the message is being discarded.
 *
 * When using `ANYRTC_DATA_CHANNEL_TYPE_*_TIMED`, the reliability
 * parameter specifies the time window in milliseconds during which
 * (re-)transmissions may occur before the message is being discarded.
 */
enum anyrtc_code anyrtc_data_channel_parameters_create(
        struct anyrtc_data_channel_parameters** const parametersp, // de-referenced
        char const * const label, // copied, nullable
        enum anyrtc_data_channel_type const channel_type,
        uint32_t const reliability_parameter,
        char const * const protocol, // copied, nullable
        bool const negotiated,
        uint16_t const id
) {
    struct anyrtc_data_channel_parameters* parameters;

    // Check arguments
    if (!parametersp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_zalloc(sizeof(*parameters), anyrtc_data_channel_parameters_destroy);
    if (!parameters) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields / copy
    if (label) {
        anyrtc_strdup(&parameters->label, label);
    }
    parameters->channel_type = channel_type;
    if (protocol) {
        anyrtc_strdup(&parameters->protocol, protocol);
    }
    parameters->negotiated = negotiated;
    if (negotiated) {
        parameters->id = id;
    }

    // Set reliability parameter
    switch (channel_type) {
        case ANYRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED:
        case ANYRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED:
            parameters->reliability_parameter = 0;
            break;
        default:
            parameters->reliability_parameter = reliability_parameter;
            break;
    }

    // Set pointer & done
    *parametersp = parameters;
    return ANYRTC_CODE_SUCCESS;
}
