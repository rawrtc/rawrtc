#include "connection.h"
#include "../peer_connection_description/description.h"
#include <rawrtc/ice_gatherer.h>
#include <rawrtc/ice_transport.h>
#include <rawrtc/peer_connection.h>
#include <rawrtc/peer_connection_state.h>
#include <rawrtcc/code.h>
#include <rawrtcdc/data_channel.h>
#include <re.h>

/*
 * Get local description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no local description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_description(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Reference description (if any)
    if (connection->local_description) {
        *descriptionp = mem_ref(connection->local_description);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get remote description.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_get_remote_description(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Reference description (if any)
    if (connection->remote_description) {
        *descriptionp = mem_ref(connection->remote_description);
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Get the current signalling state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state(
        enum rawrtc_signaling_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = connection->signaling_state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the current ICE gathering state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state(
        enum rawrtc_ice_gatherer_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    // Note: The W3C spec requires us to return 'new' in case no ICE gatherer exists.
    // Note: Theoretically there's no 'closed' state on the peer connection variant. We ignore
    //       that here.
    if (connection->context.ice_gatherer) {
        return rawrtc_ice_gatherer_get_state(statep, connection->context.ice_gatherer);
    } else {
        *statep = RAWRTC_ICE_GATHERER_STATE_NEW;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current ICE connection state of a peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state(
        enum rawrtc_ice_transport_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    // Note: The W3C spec requires us to return 'new' in case no ICE transport exists.
    if (connection->context.ice_transport) {
        return rawrtc_ice_transport_get_state(statep, connection->context.ice_transport);
    } else {
        *statep = RAWRTC_ICE_TRANSPORT_STATE_NEW;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current (peer) connection state of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state(
        enum rawrtc_peer_connection_state* const statep, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!statep || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = connection->connection_state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get indication whether the remote peer accepts trickled ICE
 * candidates.
 *
 * Returns `RAWRTC_CODE_NO_VALUE` in case no remote description has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_can_trickle_ice_candidates(
        bool* const can_trickle_ice_candidatesp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!can_trickle_ice_candidatesp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set flag (if remote description set)
    if (connection->remote_description) {
        *can_trickle_ice_candidatesp = connection->remote_description->trickle_ice;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Unset the handler argument and all handlers of the peer connection.
 */
enum rawrtc_code rawrtc_peer_connection_unset_handlers(
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Unset handler argument
    connection->arg = NULL;

    // Unset all handlers
    connection->data_channel_handler = NULL;
    connection->connection_state_change_handler = NULL;
    connection->ice_gathering_state_change_handler = NULL;
    connection->ice_connection_state_change_handler = NULL;
    connection->signaling_state_change_handler = NULL;
    connection->local_candidate_error_handler = NULL;
    connection->local_candidate_handler = NULL;
    connection->negotiation_needed_handler = NULL;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set the peer connection's negotiation needed handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_negotiation_needed_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_negotiation_needed_handler const negotiation_needed_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set negotiation needed handler & done
    connection->negotiation_needed_handler = negotiation_needed_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's negotiation needed handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_negotiation_needed_handler(
        rawrtc_negotiation_needed_handler* const negotiation_needed_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!negotiation_needed_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get negotiation needed handler (if any)
    if (connection->negotiation_needed_handler) {
        *negotiation_needed_handlerp = connection->negotiation_needed_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ICE local candidate handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_local_candidate_handler const local_candidate_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set local candidate handler & done
    connection->local_candidate_handler = local_candidate_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ICE local candidate handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_handler(
        rawrtc_peer_connection_local_candidate_handler* const local_candidate_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!local_candidate_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate handler (if any)
    if (connection->local_candidate_handler) {
        *local_candidate_handlerp = connection->local_candidate_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ICE local candidate error handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_local_candidate_error_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_local_candidate_error_handler const local_candidate_error_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set local candidate error handler & done
    connection->local_candidate_error_handler = local_candidate_error_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ICE local candidate error handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_local_candidate_error_handler(
        rawrtc_peer_connection_local_candidate_error_handler* const local_candidate_error_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!local_candidate_error_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get local candidate error handler (if any)
    if (connection->local_candidate_error_handler) {
        *local_candidate_error_handlerp = connection->local_candidate_error_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's signaling state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_signaling_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_signaling_state_change_handler const signaling_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set signaling state change handler & done
    connection->signaling_state_change_handler = signaling_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's signaling state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_signaling_state_change_handler(
        rawrtc_signaling_state_change_handler* const signaling_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!signaling_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get signaling state change handler (if any)
    if (connection->signaling_state_change_handler) {
        *signaling_state_change_handlerp = connection->signaling_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ice connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_connection_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_ice_transport_state_change_handler const ice_connection_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set ice connection state change handler & done
    connection->ice_connection_state_change_handler = ice_connection_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ice connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_connection_state_change_handler(
        rawrtc_ice_transport_state_change_handler* const ice_connection_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!ice_connection_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get ice connection state change handler (if any)
    if (connection->ice_connection_state_change_handler) {
        *ice_connection_state_change_handlerp = connection->ice_connection_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's ice gathering state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_ice_gathering_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_ice_gatherer_state_change_handler const ice_gathering_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set ice gathering state change handler & done
    connection->ice_gathering_state_change_handler = ice_gathering_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's ice gathering state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_ice_gathering_state_change_handler(
        rawrtc_ice_gatherer_state_change_handler* const ice_gathering_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!ice_gathering_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get ice gathering state change handler (if any)
    if (connection->ice_gathering_state_change_handler) {
        *ice_gathering_state_change_handlerp = connection->ice_gathering_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's (peer) connection state change handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_connection_state_change_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_peer_connection_state_change_handler const connection_state_change_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set (peer) connection state change handler & done
    connection->connection_state_change_handler = connection_state_change_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's (peer) connection state change handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_connection_state_change_handler(
        rawrtc_peer_connection_state_change_handler* const connection_state_change_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!connection_state_change_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get (peer) connection state change handler (if any)
    if (connection->connection_state_change_handler) {
        *connection_state_change_handlerp = connection->connection_state_change_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}

/*
 * Set the peer connection's data channel handler.
 */
enum rawrtc_code rawrtc_peer_connection_set_data_channel_handler(
        struct rawrtc_peer_connection* const connection,
        rawrtc_data_channel_handler const data_channel_handler // nullable
) {
    // Check arguments
    if (!connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set data channel handler & done
    connection->data_channel_handler = data_channel_handler;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the peer connection's data channel handler.
 * Returns `RAWRTC_CODE_NO_VALUE` in case no handler has been set.
 */
enum rawrtc_code rawrtc_peer_connection_get_data_channel_handler(
        rawrtc_data_channel_handler* const data_channel_handlerp, // de-referenced
        struct rawrtc_peer_connection* const connection
) {
    // Check arguments
    if (!data_channel_handlerp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get data channel handler (if any)
    if (connection->data_channel_handler) {
        *data_channel_handlerp = connection->data_channel_handler;
        return RAWRTC_CODE_SUCCESS;
    } else {
        return RAWRTC_CODE_NO_VALUE;
    }
}
