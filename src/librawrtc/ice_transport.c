#include <rawrtc.h>
#include "config.h"
#include "ice_parameters.h"
#include "ice_candidate.h"
#include "ice_gatherer.h"
#include "dtls_transport.h"
#include "ice_transport.h"

#define DEBUG_MODULE "ice-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

/*
 * Destructor for an existing ICE transport.
 */
static void rawrtc_ice_transport_destroy(
        void* arg
) {
    struct rawrtc_ice_transport* const transport = arg;

    // Stop transport
    // TODO: Check effects in case transport has been destroyed due to error in create
    rawrtc_ice_transport_stop(transport);

    // Un-reference
    mem_deref(transport->remote_parameters);
    mem_deref(transport->gatherer);
}

/*
 * Create a new ICE transport.
 * `*transportp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_transport_create(
        struct rawrtc_ice_transport** const transportp, // de-referenced
        struct rawrtc_ice_gatherer* const gatherer, // referenced, nullable
        rawrtc_ice_transport_state_change_handler* const state_change_handler, // nullable
        rawrtc_ice_transport_candidate_pair_change_handler* const candidate_pair_change_handler, // nullable
        void* const arg // nullable
) {
    struct rawrtc_ice_transport* transport;

    // Check arguments
    if (!transportp || !gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check ICE gatherer state
    // TODO: Check if gatherer.component is RTCP -> invalid state
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Allocate
    transport = mem_zalloc(sizeof(*transport), rawrtc_ice_transport_destroy);
    if (!transport) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = RAWRTC_ICE_TRANSPORT_STATE_NEW; // TODO: Raise state (delayed)?
    transport->gatherer = mem_ref(gatherer);
    transport->state_change_handler = state_change_handler;
    transport->candidate_pair_change_handler = candidate_pair_change_handler;
    transport->arg = arg;

    // Set pointer
    *transportp = transport;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 */
static void set_state(
        struct rawrtc_ice_transport* const transport,
        enum rawrtc_ice_transport_state const state
) {
    // Set state
    transport->state = state;

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }
}

/*
 * ICE connection established callback.
 */
static void ice_established_handler(
        struct ice_candpair* candidate_pair,
        struct stun_msg const* message,
        void* arg
) {
    struct rawrtc_ice_transport* const transport = arg;
    enum rawrtc_code error;
    (void) message;

    DEBUG_PRINTF("Candidate pair established: %H\n", trice_candpair_debug, candidate_pair);

    // Ignore if closed
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return;
    }

    // State: checking -> connected
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CHECKING) {
        DEBUG_INFO("ICE connection established\n");
        set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_CONNECTED);
    }

    // TODO: Re-enable once 'completed' state has been fixed
//    // Ignore if completed
//    // Note: This case can happen when the checklist is completed but an ICE candidate triggers
//    //       a late failed event.
//    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_COMPLETED) {
//        return;
//    }

    // Offer candidate pair to DTLS transport (if any)
    // TODO: Offer to whatever transport lays above so we are SRTP/QUIC compatible
    if (transport->dtls_transport) {
        error = rawrtc_dtls_transport_add_candidate_pair(
                transport->dtls_transport, candidate_pair);
        if (error) {
            DEBUG_WARNING("DTLS transport could not attach to candidate pair, reason: %s\n",
                          rawrtc_code_to_str(error));

            // Remove candidate pair
            mem_deref(candidate_pair);
        }
    }

    // TODO: Call candidate_pair_change_handler (?)

    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(transport->gatherer->ice)) {
        DEBUG_INFO("Checklist completed:\n%H", trice_debug, transport->gatherer->ice);

//        // At least one candidate pair succeeded, transition to completed
//        DEBUG_INFO("ICE connection completed\n");
//        // TODO: ORTC spec says: Only transition to completed if end-of-candidates has been added
//        //       by both
//        set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_COMPLETED);
    }
}

/*
 * ICE connection failed callback.
 */
static void ice_failed_handler(
        int err,
        uint16_t stun_code,
        struct ice_candpair* candidate_pair,
        void* arg
) {
    struct rawrtc_ice_transport* const transport = arg;
    (void) err; (void) stun_code; (void) candidate_pair;

    DEBUG_PRINTF("Candidate pair failed: %H (%m %"PRIu16")\n",
                 trice_candpair_debug, candidate_pair, err, stun_code);

    // Ignore if closed
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return;
    }

    // Ignore if completed
    // Note: This case can happen when the checklist is completed but an ICE candidate triggers
    //       a late failed event.
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_COMPLETED) {
        return;
    }

    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(transport->gatherer->ice)) {
        DEBUG_INFO("Checklist completed:\n%H", trice_debug, transport->gatherer->ice);

        // Do we have one candidate pair that succeeded?
        if (!list_isempty(trice_validl(transport->gatherer->ice))) {
            // Yes, transition to completed
            DEBUG_INFO("ICE connection completed\n");
            // TODO: ORTC spec says: Only transition to completed if end-of-candidates has been
            //       added by both
            set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_COMPLETED);
        } else {
            // No, transition to failed
            DEBUG_INFO("ICE connection failed\n");
            set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_FAILED);
        }
    }
}

/*
 * Start the ICE transport.
 * TODO https://github.com/w3c/ortc/issues/607
 */
enum rawrtc_code rawrtc_ice_transport_start(
        struct rawrtc_ice_transport* const transport,
        struct rawrtc_ice_gatherer* const gatherer, // referenced
        struct rawrtc_ice_parameters* const remote_parameters, // referenced
        enum rawrtc_ice_role const role
) {
    bool ice_transport_closed;
    bool ice_gatherer_closed;
    enum ice_role translated_role;
    enum rawrtc_code error;

    // Check arguments
    if (!transport || !gatherer || !remote_parameters) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate parameters
    if (!remote_parameters->username_fragment || !remote_parameters->password) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Handle ICE lite
    if (remote_parameters->ice_lite) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // TODO: Check that components of ICE gatherer and ICE transport match

    // Check state
    ice_transport_closed = transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED;
    ice_gatherer_closed = gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED;
    if (ice_transport_closed || ice_gatherer_closed) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // TODO: Handle ICE restart when called again
    if (transport->state != RAWRTC_ICE_TRANSPORT_STATE_NEW) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check if gatherer instance is different
    // TODO https://github.com/w3c/ortc/issues/607
    if (transport->gatherer != gatherer) {
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Set role (abort if unknown or something entirely weird)
    translated_role = rawrtc_ice_role_to_re_ice_role(role);
    error = rawrtc_error_to_code(trice_set_role(transport->gatherer->ice, translated_role));
    if (error) {
        return error;
    }

    // New/first remote parameters?
    if (transport->remote_parameters != remote_parameters) {
        // Apply username fragment and password on trice
        error = rawrtc_error_to_code(trice_set_remote_ufrag(
                transport->gatherer->ice, remote_parameters->username_fragment));
        if (error) {
            return error;
        }
        error = rawrtc_error_to_code(trice_set_remote_pwd(
                transport->gatherer->ice, remote_parameters->password));
        if (error) {
            return error;
        }

        // Replace
        mem_deref(transport->remote_parameters);
        transport->remote_parameters = mem_ref(remote_parameters);
    }

    // Set state to checking
    // TODO: Get more states from trice
    // TODO: Is this actually correct if we don't have any remote candidates?
    set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_CHECKING);

    // Start checklist (if remote candidates exist)
    if (!list_isempty(trice_rcandl(transport->gatherer->ice))) {
        // TODO: Get config from struct
        // TODO: Why are there no keep-alive messages?
        // TODO: Set 'use_cand' properly
        DEBUG_INFO("Starting checklist due to start event\n");
        error = rawrtc_error_to_code(trice_checklist_start(
                transport->gatherer->ice, NULL, rawrtc_default_config.pacing_interval,
                ice_established_handler, ice_failed_handler, transport));
        if (error) {
            return error;
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Stop and close the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_stop(
        struct rawrtc_ice_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Already closed?
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Stop ICE checklist (if running)
    if (trice_checklist_isrunning(transport->gatherer->ice)) {
        trice_checklist_stop(transport->gatherer->ice);
    }

    // TODO: Remove remote candidates, role, username fragment and password from rew

    // TODO: Remove from RTCICETransportController (once we have it)

    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the current ICE role of the ICE transport.
 * Return `RAWRTC_CODE_NO_VALUE` code in case the ICE role has not been
 * determined yet.
 */
enum rawrtc_code rawrtc_ice_transport_get_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        struct rawrtc_ice_transport* const transport
) {
    enum ice_role re_role;
    enum rawrtc_code error;
    enum rawrtc_ice_role role;

    // Check arguments
    if (!rolep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get libre role from ICE instance
    re_role = trice_local_role(transport->gatherer->ice);

    // Translate role
    error = rawrtc_re_ice_role_to_ice_role(&role, re_role);
    if (error) {
        return error;
    }

    // Unknown?
    if (re_role == ICE_ROLE_UNKNOWN) {
        return RAWRTC_CODE_NO_VALUE;
    } else {
        // Set pointer
        *rolep = role;
        return RAWRTC_CODE_SUCCESS;
    }
}

/*
 * Get the current state of the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_get_state(
        enum rawrtc_ice_transport_state* const statep, // de-referenced
        struct rawrtc_ice_transport* const transport
) {
    // Check arguments
    if (!statep || !transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state & done
    *statep = transport->state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add a remote candidate ot the ICE transport.
 * Note: 'candidate' must be NULL to inform the transport that the
 * remote site finished gathering.
 */
enum rawrtc_code rawrtc_ice_transport_add_remote_candidate(
        struct rawrtc_ice_transport* const transport,
        struct rawrtc_ice_candidate* candidate // nullable
) {
    struct ice_rcand* re_candidate = NULL;
    enum rawrtc_code error;
    char* ip = NULL;
    uint16_t port;
    struct sa address = {{{0}}};
    int af;
    enum rawrtc_ice_protocol protocol;
    char* foundation = NULL;
    uint32_t priority;
    enum rawrtc_ice_candidate_type type;
    enum rawrtc_ice_tcp_candidate_type tcp_type;
    char* related_address = NULL;

    // Check arguments
    if (!transport) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check ICE transport state
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Remote site completed gathering?
    if (!candidate) {
        DEBUG_PRINTF("Remote site gathering complete\n%H", trice_debug, transport->gatherer->ice);
        // TODO: Transition to complete if both have completed gathering
        return RAWRTC_CODE_SUCCESS;
    }

    // Get IP and port
    error = rawrtc_ice_candidate_get_ip(&ip, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_port(&port, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_error_to_code(sa_set_str(&address, ip, port));
    if (error) {
        goto out;
    }

    // Skip IPv4, IPv6 if requested
    // TODO: Get config from struct
    af = sa_af(&address);
    if ((!rawrtc_default_config.ipv6_enable && af == AF_INET6)
            || (!rawrtc_default_config.ipv4_enable && af == AF_INET)) {
        DEBUG_PRINTF("Skipping remote candidate due to IP version: %J\n", &address);
        goto out;
    }

    // Get protocol
    error = rawrtc_ice_candidate_get_protocol(&protocol, candidate);
    if (error) {
        goto out;
    }

    // Skip UDP/TCP if requested
    // TODO: Get config from struct
    if ((!rawrtc_default_config.udp_enable && protocol == RAWRTC_ICE_PROTOCOL_UDP)
            || (!rawrtc_default_config.tcp_enable && protocol == RAWRTC_ICE_PROTOCOL_TCP)) {
        DEBUG_PRINTF("Skipping remote candidate due to protocol: %J\n", &address);
        goto out;
    }

    // Get necessary vars
    error = rawrtc_ice_candidate_get_foundation(&foundation, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_protocol(&protocol, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_priority(&priority, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_type(&type, candidate);
    if (error) {
        goto out;
    }
    error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
    switch (error) {
        case RAWRTC_CODE_SUCCESS:
            break;
        case RAWRTC_CODE_NO_VALUE:
            // Doesn't matter what we choose here, protocol is not TCP anyway
            tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
            break;
        default:
            goto out;
    }

    // Add remote candidate
    // TODO: Set correct component ID
    error = rawrtc_error_to_code(trice_rcand_add(
            &re_candidate, transport->gatherer->ice, 1, foundation,
            rawrtc_ice_protocol_to_ipproto(protocol), priority, &address,
            rawrtc_ice_candidate_type_to_ice_cand_type(type),
            rawrtc_ice_tcp_candidate_type_to_ice_tcptype(tcp_type)));
    if (error) {
        goto out;
    }

    // Set related address (if any)
    error = rawrtc_ice_candidate_get_related_address(&related_address, candidate);
    if (!error) {
        error = rawrtc_ice_candidate_get_related_port(&port, candidate);
        if (!error) {
            error = rawrtc_error_to_code(sa_set_str(
                    &re_candidate->attr.rel_addr, related_address, port));
            if (error) {
                goto out;
            }
        }
    }
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        goto out;
    }

    // TODO: Add TURN permission

    // Done
    DEBUG_PRINTF("Added remote candidate: %J\n", &address);
    error = RAWRTC_CODE_SUCCESS;

    // Start checklist (if not started)
    // TODO: Get config from struct
    // TODO: Why are there no keep-alive messages?
    // TODO: Set 'use_cand' properly
    if (transport->state != RAWRTC_ICE_TRANSPORT_STATE_NEW &&
            !trice_checklist_isrunning(transport->gatherer->ice)) {
        DEBUG_INFO("Starting checklist due to new remote candidate\n");
        error = rawrtc_error_to_code(trice_checklist_start(
                transport->gatherer->ice, NULL, rawrtc_default_config.pacing_interval,
                ice_established_handler, ice_failed_handler, transport));
        if (error) {
            DEBUG_WARNING("Could not start checklist, reason: %s\n", rawrtc_code_to_str(error));
            goto out;
        }
    }

out:
    if (error) {
        mem_deref(re_candidate); // TODO: Not entirely sure about that
    }

    // Free vars
    mem_deref(related_address);
    mem_deref(foundation);
    mem_deref(ip);

    return error;
}

/*
 * Set the remote candidates on the ICE transport overwriting all
 * existing remote candidates.
 */
enum rawrtc_code rawrtc_ice_transport_set_remote_candidates(
        struct rawrtc_ice_transport* const transport,
        struct rawrtc_ice_candidate* const candidates[], // referenced (each item)
        size_t const n_candidates
) {
    size_t i;
    enum rawrtc_code error;

    // Check arguments
    if (!transport || !candidates) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Our implementation is incorrect here, it should remove
    //       previously added remote candidates and replace them. Fix this
    //       once we can handle an ICE restart.

    // Add each remote candidate
    for (i = 0; i < n_candidates; ++i) {
        error = rawrtc_ice_transport_add_remote_candidate(transport, candidates[i]);
        if (error) {
            return error;
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const rawrtc_ice_transport_state_to_name(
        enum rawrtc_ice_transport_state const state
) {
    switch (state) {
        case RAWRTC_ICE_TRANSPORT_STATE_NEW:
            return "new";
        case RAWRTC_ICE_TRANSPORT_STATE_CHECKING:
            return "checking";
        case RAWRTC_ICE_TRANSPORT_STATE_CONNECTED:
            return "connected";
        case RAWRTC_ICE_TRANSPORT_STATE_COMPLETED:
            return "completed";
        case RAWRTC_ICE_TRANSPORT_STATE_DISCONNECTED:
            return "disconnected";
        case RAWRTC_ICE_TRANSPORT_STATE_FAILED:
            return "failed";
        case RAWRTC_ICE_TRANSPORT_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

static enum rawrtc_ice_role const map_enum_ice_role[] = {
    RAWRTC_ICE_ROLE_CONTROLLING,
    RAWRTC_ICE_ROLE_CONTROLLED,
};

static char const * const map_str_ice_role[] = {
    "controlling",
    "controlled",
};

static size_t const map_ice_role_length = ARRAY_SIZE(map_enum_ice_role);

/*
 * Translate an ICE role to str.
 */
char const * rawrtc_ice_role_to_str(
        enum rawrtc_ice_role const role
) {
    size_t i;

    for (i = 0; i < map_ice_role_length; ++i) {
        if (map_enum_ice_role[i] == role) {
            return map_str_ice_role[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an ICE role (case-insensitive).
 */
enum rawrtc_code rawrtc_str_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!rolep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_ice_role_length; ++i) {
        if (str_casecmp(map_str_ice_role[i], str) == 0) {
            *rolep = map_enum_ice_role[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Translate an ICE role to the corresponding re type.
 */
enum ice_role rawrtc_ice_role_to_re_ice_role(
        enum rawrtc_ice_role const role
) {
    // No conversion needed
    return (enum ice_role) role;
}

/*
 * Translate a re ICE role to the corresponding rawrtc role.
 */
enum rawrtc_code rawrtc_re_ice_role_to_ice_role(
        enum rawrtc_ice_role* const rolep, // de-referenced
        enum ice_role const re_role
) {
    // Check arguments
    if (!rolep) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Translate role
    switch (re_role) {
        case ICE_ROLE_CONTROLLING:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLING;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_CONTROLLED:
            *rolep = RAWRTC_ICE_ROLE_CONTROLLED;
            return RAWRTC_CODE_SUCCESS;
        case ICE_ROLE_UNKNOWN:
            *rolep = RAWRTC_ICE_ROLE_UNKNOWN;
            return RAWRTC_CODE_SUCCESS;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }
}
