#include <anyrtc.h>
#include "data_transport.h"

#define DEBUG_MODULE "data-channel"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Change the state of the data channel.
 * Will call the corresponding handler.
 * Caller MUST ensure that the same state is not set twice.
 */
void anyrtc_data_channel_set_state(
        struct anyrtc_data_channel* const channel, // not checked
        enum anyrtc_data_channel_state const state
) {
    enum anyrtc_code error;

    // Set state
    channel->state = state;

    // Call transport handler (if any) and user application handler
    switch (state) {
        case ANYRTC_DATA_CHANNEL_STATE_OPEN:
            // Call handler
            if (channel->open_handler) {
                channel->open_handler(channel->arg);
            }
            break;

        case ANYRTC_DATA_CHANNEL_STATE_CLOSED:
            // Warning: To close the channel, use `anyrtc_data_channel_close`!

            // Call transport close handler
            error = channel->transport->channel_close(channel);
            if (error) {
                DEBUG_WARNING("Unable to close data channel, reason: %s\n", anyrtc_code_to_str(error));
            }

            // Call handler
            if (channel->close_handler) {
                channel->close_handler(channel->arg);
            }
            break;
        default:
            break;
    }
}

/*
 * Destructor for an existing data channel.
 */
static void anyrtc_data_channel_destroy(
        void* const arg
) {
    struct anyrtc_data_channel* const channel = arg;

    // Close channel
    // Note: Don't close before NEW
    if (channel->state != ANYRTC_DATA_CHANNEL_STATE_INIT) {
        anyrtc_data_channel_close(channel);
    }

    // Dereference
    mem_deref(channel->transport);
    mem_deref(channel->transport_arg);
    mem_deref(channel->parameters);
}

/*
 * Create a data channel.
 */
enum anyrtc_code anyrtc_data_channel_create(
        struct anyrtc_data_channel** const channelp, // de-referenced
        struct anyrtc_data_transport* const transport, // referenced
        struct anyrtc_data_channel_parameters* const parameters, // referenced
        anyrtc_data_channel_open_handler* const open_handler, // nullable
        anyrtc_data_channel_buffered_amount_low_handler* const buffered_amount_low_handler, // nullable
        anyrtc_data_channel_error_handler* const error_handler, // nullable
        anyrtc_data_channel_close_handler* const close_handler, // nullable
        anyrtc_data_channel_message_handler* const message_handler,
        void* const arg // nullable
) {
    enum anyrtc_code error;
    struct anyrtc_data_channel* channel;

    // Check arguments
    if (!channelp || !transport || !parameters || !message_handler) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    channel = mem_zalloc(sizeof(*channel), anyrtc_data_channel_destroy);
    if (!channel) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    channel->state = ANYRTC_DATA_CHANNEL_STATE_INIT;
    channel->transport = mem_ref(transport);
    channel->parameters = mem_ref(parameters);
    channel->open_handler = open_handler;
    channel->buffered_amount_low_handler = buffered_amount_low_handler;
    channel->error_handler = error_handler;
    channel->close_handler = close_handler;
    channel->message_handler = message_handler;
    channel->arg = arg;

    // Create data channel on transport
    error = transport->channel_create(transport, channel, parameters);
    if (error) {
        goto out;
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
        if (channel->state == ANYRTC_DATA_CHANNEL_STATE_INIT) {
            channel->state = ANYRTC_DATA_CHANNEL_STATE_NEW;
        }
        *channelp = channel;
    }
    return error;
}

/*
 * Close the data channel.
 */
enum anyrtc_code anyrtc_data_channel_close(
        struct anyrtc_data_channel* const channel
) {
    // Check arguments
    if (!channel) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (channel->state == ANYRTC_DATA_CHANNEL_STATE_CLOSED) {
        return ANYRTC_CODE_SUCCESS;
    }

    // Update state
    anyrtc_data_channel_set_state(channel, ANYRTC_DATA_CHANNEL_STATE_CLOSED);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the data channel's parameters.
 */
enum anyrtc_code anyrtc_data_channel_get_parameters(
        struct anyrtc_data_channel_parameters** const parametersp, // de-referenced
        struct anyrtc_data_channel* const channel
) {
    // Check arguments
    if (!parametersp || !channel) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set pointer & done
    *parametersp = channel->parameters;
    return ANYRTC_CODE_SUCCESS;
}
