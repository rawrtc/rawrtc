#include <rawrtc.h>
#include "data_channel_parameters.h"

/*
 * Destructor for existing data channel parameters.
 */
static void rawrtc_data_channel_parameters_destroy(
        void* arg
) {
    struct rawrtc_data_channel_parameters* const parameters = arg;

    // Un-reference
    mem_deref(parameters->label);
    mem_deref(parameters->protocol);
}

enum rawrtc_code data_parameters_create(
        struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
        char* const label, // referenced, nullable
        enum rawrtc_data_channel_type const channel_type,
        uint32_t const reliability_parameter,
        char* const protocol, // referenced, nullable
        bool const negotiated,
        uint16_t const id
) {
    struct rawrtc_data_channel_parameters* parameters;

    // Check arguments
    if (!parametersp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    parameters = mem_zalloc(sizeof(*parameters), rawrtc_data_channel_parameters_destroy);
    if (!parameters) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields
    parameters->label = label;
    parameters->protocol = protocol;
    parameters->channel_type = channel_type;
    parameters->negotiated = negotiated;
    if (negotiated) {
        parameters->id = id;
    }

    // Set reliability parameter
    switch (channel_type) {
        case RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_ORDERED:
        case RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_UNORDERED:
            parameters->reliability_parameter = 0;
            break;
        default:
            parameters->reliability_parameter = reliability_parameter;
            break;
    }

    // Set pointer & done
    *parametersp = parameters;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create data channel parameters (internal).
 */
enum rawrtc_code rawrtc_data_channel_parameters_create_internal(
        struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
        char* const label, // referenced, nullable
        enum rawrtc_data_channel_type const channel_type,
        uint32_t const reliability_parameter,
        char* const protocol, // referenced, nullable
        bool const negotiated,
        uint16_t const id
) {
    enum rawrtc_code error;

    // Create parameters
    error = data_parameters_create(
            parametersp, label, channel_type, reliability_parameter, protocol, negotiated, id);

    if (!error) {
        // Reference label & protocol
        mem_ref(label);
        mem_ref(protocol);
    }

    // Done
    return error;
}

/*
 * Create data channel parameters.
 *
 * For `RAWRTC_DATA_CHANNEL_TYPE_RELIABLE_*`, the reliability parameter
 * is being ignored.
 *
 * When using `RAWRTC_DATA_CHANNEL_TYPE_*_RETRANSMIT`, the reliability
 * parameter specifies the number of times a retransmission occurs if
 * not acknowledged before the message is being discarded.
 *
 * When using `RAWRTC_DATA_CHANNEL_TYPE_*_TIMED`, the reliability
 * parameter specifies the time window in milliseconds during which
 * (re-)transmissions may occur before the message is being discarded.
 */
enum rawrtc_code rawrtc_data_channel_parameters_create(
        struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
        char const * const label, // copied, nullable
        enum rawrtc_data_channel_type const channel_type,
        uint32_t const reliability_parameter,
        char const * const protocol, // copied, nullable
        bool const negotiated,
        uint16_t const id
) {
    char* copied_label;
    char* copied_protocol;
    enum rawrtc_code error;

    // Copy label
    if (label) {
        rawrtc_strdup(&copied_label, label);
    } else {
        copied_label = NULL;
    }

    // Copy protocol
    if (protocol) {
        rawrtc_strdup(&copied_protocol, protocol);
    } else {
        copied_protocol = NULL;
    }

    // Create parameters
    error = data_parameters_create(
            parametersp, copied_label, channel_type, reliability_parameter, copied_protocol,
            negotiated, id);

    if (error) {
        // Un-reference
        mem_deref(copied_label);
        mem_deref(copied_protocol);
    }

    // Done
    return error;
}

/*
 * Get the label from the data channel parameters.
 * Return `RAWRTC_CODE_NO_VALUE` in case no label has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*labelp*
 * must be unreferenced.
 */
enum rawrtc_code rawrtc_data_channel_parameters_get_label(
        char** const labelp, // de-referenced
        struct rawrtc_data_channel_parameters* const parameters
) {
    // Check arguments
    if (!labelp || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    if (parameters->label) {
        *labelp = mem_ref(parameters->label);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the protocol from the data channel parameters.
 * Return `RAWRTC_CODE_NO_VALUE` in case no protocol has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*protocolp*
 * must be unreferenced.
 */
enum rawrtc_code rawrtc_data_channel_parameters_get_protocol(
        char** const protocolp, // de-referenced
        struct rawrtc_data_channel_parameters* const parameters
) {
    // Check arguments
    if (!protocolp || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value
    if (parameters->protocol) {
        *protocolp = mem_ref(parameters->protocol);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}
