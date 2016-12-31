#include <rawrtc.h>
#include "utils.h"
#include "data_transport.h"

#define DEBUG_MODULE "data-channel"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Change the state of the data channel.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
void rawrtc_data_channel_set_state(
        struct rawrtc_data_channel* const channel, // not checked
        enum rawrtc_data_channel_state const state
) {
    enum rawrtc_code error;

    // Set state
    channel->state = state;

    // Call transport handler (if any) and user application handler
    switch (state) {
        case RAWRTC_DATA_CHANNEL_STATE_OPEN:
            // Call handler
            if (channel->open_handler) {
                channel->open_handler(channel->arg);
            }
            break;

        case RAWRTC_DATA_CHANNEL_STATE_CLOSED:
            // Warning: To close the channel, use `rawrtc_data_channel_close`!

            // Note: We need to reference ourselves because the channel close handler may hold
            //       and release the very last reference to this instance in the call.
            mem_ref(channel);

            // Call transport close handler
            error = channel->transport->channel_close(channel);
            if (error) {
                DEBUG_WARNING("Unable to close data channel, reason: %s\n", rawrtc_code_to_str(error));
            }

            // Call handler
            if (channel->close_handler) {
                channel->close_handler(channel->arg);
            }

            // Done
            mem_deref(channel);
            break;
        default:
            break;
    }
}

/*
 * Destructor for an existing data channel.
 */
static void rawrtc_data_channel_destroy(
        void* const arg
) {
    struct rawrtc_data_channel* const channel = arg;

    // Close channel
    // Note: Don't close before NEW
    if (channel->state != RAWRTC_DATA_CHANNEL_STATE_INIT) {
        rawrtc_data_channel_close(channel);
    }

    // Dereference
    mem_deref(channel->transport);
    mem_deref(channel->transport_arg);
    mem_deref(channel->parameters);

    // Dereference options
    if (channel->options != &rawrtc_default_data_channel_options) {
        mem_deref(channel->options);
    }
}

/*
 * Set options on a data channel (internal).
 *
 * Warning: The caller MUST ensure that this function is being used
 * before any messages is being received on the data channel!
 */
enum rawrtc_code rawrtc_data_channel_set_options(
        struct rawrtc_data_channel* const channel,
        struct rawrtc_data_channel_options* options // nullable, referenced
) {
    // Check arguments
    if (!channel) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Default options
    if (!options) {
        options = &rawrtc_default_data_channel_options;
    }

    // Clear previos options
    if (channel->options && channel->options != &rawrtc_default_data_channel_options) {
        mem_deref(channel->options);
    }

    // Set options
    if (options == &rawrtc_default_data_channel_options) {
        channel->options = options;
    } else {
        channel->options = mem_ref(options);
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Create a data channel (internal).
 */
enum rawrtc_code rawrtc_data_channel_create_internal(
        struct rawrtc_data_channel** const channelp, // de-referenced
        struct rawrtc_data_transport* const transport, // referenced
        struct rawrtc_data_channel_parameters* const parameters, // referenced
        struct rawrtc_data_channel_options* options, // nullable, referenced
        rawrtc_data_channel_open_handler* const open_handler, // nullable
        rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
        rawrtc_data_channel_error_handler* const error_handler, // nullable
        rawrtc_data_channel_close_handler* const close_handler, // nullable
        rawrtc_data_channel_message_handler* const message_handler, // nullable
        void* const arg, // nullable
        bool const call_handler
) {
    enum rawrtc_code error;
    struct rawrtc_data_channel *channel;

    // Check arguments
    if (!channelp || !transport || !parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    channel = mem_zalloc(sizeof(*channel), rawrtc_data_channel_destroy);
    if (!channel) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    channel->state = RAWRTC_DATA_CHANNEL_STATE_INIT;
    channel->transport = mem_ref(transport);
    channel->parameters = mem_ref(parameters);
    channel->open_handler = open_handler;
    channel->buffered_amount_low_handler = buffered_amount_low_handler;
    channel->error_handler = error_handler;
    channel->close_handler = close_handler;
    channel->message_handler = message_handler;
    channel->arg = arg;

    // Set options
    error = rawrtc_data_channel_set_options(channel, options);
    if (error) {
        goto out;
    }

    // Create data channel on transport
    if (call_handler) {
        error = transport->channel_create(transport, channel, parameters);
        if (error) {
            goto out;
        }
    } else {
        error = RAWRTC_CODE_SUCCESS;
    }

    // Done
    DEBUG_PRINTF("Created data channel: %s, protocol: %s\n",
                 parameters->label ? parameters->label : "N/A",
                 parameters->protocol ? parameters->protocol : "N/A");

out:
    if (error) {
        mem_deref(channel);
    } else {
        // Update state (if necessary) & set pointer
        if (channel->state == RAWRTC_DATA_CHANNEL_STATE_INIT) {
            channel->state = RAWRTC_DATA_CHANNEL_STATE_NEW;
        }
        *channelp = channel;
    }
    return error;
}

/*
 * Create a data channel.
 */
enum rawrtc_code rawrtc_data_channel_create(
        struct rawrtc_data_channel** const channelp, // de-referenced
        struct rawrtc_data_transport* const transport, // referenced
        struct rawrtc_data_channel_parameters* const parameters, // referenced
        struct rawrtc_data_channel_options* const options, // nullable, referenced
        rawrtc_data_channel_open_handler* const open_handler, // nullable
        rawrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
        rawrtc_data_channel_error_handler* const error_handler, // nullable
        rawrtc_data_channel_close_handler* const close_handler, // nullable
        rawrtc_data_channel_message_handler* const message_handler, // nullable
        void* const arg // nullable
) {
    return rawrtc_data_channel_create_internal(
            channelp, transport, parameters, options,
            open_handler, buffered_amount_low_handler,
            error_handler, close_handler, message_handler,
            arg, true);
}

/*
 * Send data via the data channel.
 * TODO: Add binary/string flag
 */
enum rawrtc_code rawrtc_data_channel_send(
        struct rawrtc_data_channel* const channel,
        struct mbuf* const buffer, // nullable (if empty message), referenced
        bool const is_binary
) {
    // Call handler
    return channel->transport->channel_send(channel, buffer, is_binary);
}

/*
 * Close the data channel.
 */
enum rawrtc_code rawrtc_data_channel_close(
        struct rawrtc_data_channel* const channel
) {
    // Check arguments
    if (!channel) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (channel->state == RAWRTC_DATA_CHANNEL_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Update state
    rawrtc_data_channel_set_state(channel, RAWRTC_DATA_CHANNEL_STATE_CLOSED);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the data channel's parameters.
 */
enum rawrtc_code rawrtc_data_channel_get_parameters(
        struct rawrtc_data_channel_parameters** const parametersp, // de-referenced
        struct rawrtc_data_channel* const channel
) {
    // Check arguments
    if (!parametersp || !channel) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer & done
    *parametersp = mem_ref(channel->parameters);
    return RAWRTC_CODE_SUCCESS;
}
