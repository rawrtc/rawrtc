#include <anyrtc.h>
#include "ice_transport.h"
#include "dtls_transport.h"
#include "utils.h"

#define DEBUG_MODULE "ice-transport"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Get the corresponding name for an ICE transport state.
 */
char const * const anyrtc_ice_transport_state_to_name(
        enum anyrtc_ice_transport_state const state
) {
    switch (state) {
        case ANYRTC_ICE_TRANSPORT_NEW:
            return "new";
        case ANYRTC_ICE_TRANSPORT_CHECKING:
            return "checking";
        case ANYRTC_ICE_TRANSPORT_CONNECTED:
            return "connected";
        case ANYRTC_ICE_TRANSPORT_COMPLETED:
            return "completed";
        case ANYRTC_ICE_TRANSPORT_DISCONNECTED:
            return "disconnected";
        case ANYRTC_ICE_TRANSPORT_FAILED:
            return "failed";
        case ANYRTC_ICE_TRANSPORT_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Destructor for an existing ICE transport.
 */
static void anyrtc_ice_transport_destroy(
        void* const arg
) {
    struct anyrtc_ice_transport* const transport = arg;

    // Dereference
    mem_deref(transport->remote_parameters);
    mem_deref(transport->gatherer);
}

/*
 * Create a new ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_create(
        struct anyrtc_ice_transport** const transportp, // de-referenced
        struct anyrtc_ice_gatherer* const gatherer, // referenced, nullable
        anyrtc_ice_transport_state_change_handler* const state_change_handler, // nullable
        anyrtc_ice_transport_candidate_pair_change_handler* const candidate_pair_change_handler, // nullable
        void* const arg // nullable
) {
    struct anyrtc_ice_transport* transport;

    // Check arguments
    if (!transportp || !gatherer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check ICE gatherer state
    // TODO: Check if gatherer.component is RTCP -> invalid state
    if (gatherer->state == ANYRTC_ICE_GATHERER_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Allocate
    transport = mem_zalloc(sizeof(struct anyrtc_ice_transport), anyrtc_ice_transport_destroy);
    if (!transport) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    transport->state = ANYRTC_ICE_TRANSPORT_NEW;
    transport->gatherer = mem_ref(gatherer);
    transport->state_change_handler = state_change_handler;
    transport->candidate_pair_change_handler = candidate_pair_change_handler;
    transport->arg = arg;

    // Set pointer
    *transportp = transport;
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 */
static enum anyrtc_code set_state(
        struct anyrtc_ice_transport* const transport,
        enum anyrtc_ice_transport_state const state
) {
    // Set state
    transport->state = state;

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }

    return ANYRTC_CODE_SUCCESS;
}

/*
 * ICE connection established callback.
 */
static void ice_established_handler(
        struct ice_candpair* const candidate_pair,
        struct stun_msg const* const message,
        void* const arg
) {
    struct anyrtc_ice_transport* const transport = arg;
    enum anyrtc_code error;
    (void) message;

    DEBUG_PRINTF("Candidate pair established: %H\n", trice_candpair_debug, candidate_pair);

    // Ignore if closed
    if (transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return;
    }

    // State: checking -> connected
    if (transport->state != ANYRTC_ICE_TRANSPORT_CONNECTED) {
        set_state(transport, ANYRTC_ICE_TRANSPORT_CONNECTED);
    }

    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(transport->gatherer->ice)) {
        DEBUG_PRINTF("%H", trice_debug, transport->gatherer->ice);

        // At least one candidate pair succeeded, transition to completed
        set_state(transport, ANYRTC_ICE_TRANSPORT_COMPLETED);
    }

    // Offer candidate pair to DTLS transport (if any)
    if (transport->dtls_transport) {
        error = anyrtc_dtls_transport_add_candidate_pair(
                transport->dtls_transport, candidate_pair);
        if (error) {
            DEBUG_WARNING("DTLS transport could not attach to candidate pair, reason: %s\n",
                          anyrtc_code_to_str(error));
        }
    }

    // TODO: Call candidate_pair_change_handler (?)
}

/*
 * ICE connection failed callback.
 */
static void ice_failed_handler(
        int err,
        uint16_t stun_code,
        struct ice_candpair* const candidate_pair,
        void* const arg
) {
    struct anyrtc_ice_transport* const transport = arg;

    DEBUG_PRINTF("Candidate pair failed: %H (%m %"PRIu16")\n",
                 trice_candpair_debug, candidate_pair, err, stun_code);

    // Ignore if closed
    if (transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return;
    }

    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(transport->gatherer->ice)) {
        DEBUG_PRINTF("%H", trice_debug, transport->gatherer->ice);

        // Do we have one candidate pair that succeeded?
        if (list_head(trice_validl(transport->gatherer->ice))) {
            // Yes, transition to completed
            set_state(transport, ANYRTC_ICE_TRANSPORT_COMPLETED);
        } else {
            // No, transition to failed
            set_state(transport, ANYRTC_ICE_TRANSPORT_FAILED);
        }
    }
}

/*
 * Start the ICE transport.
 * TODO https://github.com/w3c/ortc/issues/607
 */
enum anyrtc_code anyrtc_ice_transport_start(
        struct anyrtc_ice_transport* const transport,
        struct anyrtc_ice_gatherer* const gatherer, // referenced
        struct anyrtc_ice_parameters* const remote_parameters, // referenced
        enum anyrtc_ice_role const role
) {
    bool ice_transport_closed;
    bool ice_gatherer_closed;
    enum trice_role translated_role;
    enum anyrtc_code error;

    // Check arguments
    if (!transport || !gatherer || !remote_parameters) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate parameters
    if (!remote_parameters->username_fragment || !remote_parameters->password) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Handle ICE lite
    if (remote_parameters->ice_lite) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // TODO: Check that components of ICE gatherer and ICE transport match

    // Check state
    ice_transport_closed = transport->state == ANYRTC_ICE_TRANSPORT_CLOSED;
    ice_gatherer_closed = gatherer->state == ANYRTC_ICE_GATHERER_CLOSED;
    if (ice_transport_closed || ice_gatherer_closed) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // TODO: Handle ICE restart when called again
    if (transport->state != ANYRTC_ICE_TRANSPORT_NEW) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // Check if gatherer instance is different
    // TODO https://github.com/w3c/ortc/issues/607
    if (transport->gatherer != gatherer) {
        return ANYRTC_CODE_NOT_IMPLEMENTED;
    }

    // Set role (abort if unknown or something entirely weird)
    translated_role = anyrtc_translate_ice_role(role);
    error = anyrtc_translate_re_code(trice_set_role(transport->gatherer->ice, translated_role));
    if (error) {
        return error;
    }

    // New/first remote parameters?
    if (transport->remote_parameters != remote_parameters) {
        // Apply username fragment and password on trice
        error = anyrtc_translate_re_code(trice_set_remote_ufrag(
                transport->gatherer->ice, remote_parameters->username_fragment));
        if (error) {
            return error;
        }
        error = anyrtc_translate_re_code(trice_set_remote_pwd(
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
    error = set_state(transport, ANYRTC_ICE_TRANSPORT_CHECKING);
    if (error) {
        return error;
    }

    // Starting checklist
    // TODO: Is this the correct place?
    // TODO: Get config from struct
    // TODO: Why are there no keep-alive messages?
    // TODO: Set 'use_cand' properly
    error = anyrtc_translate_re_code(trice_checklist_start(
            transport->gatherer->ice, NULL, anyrtc_default_config.pacing_interval, true,
            ice_established_handler, ice_failed_handler, transport));
    if (error) {
        return error;
    }

    // TODO: Debug only
    DEBUG_PRINTF("%H", trice_debug, gatherer->ice);
    return ANYRTC_CODE_SUCCESS;
}

/*
 * Stop and close the ICE transport.
 */
enum anyrtc_code anyrtc_ice_transport_stop(
        struct anyrtc_ice_transport* const transport
) {
    // Check arguments
    if (!transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Already closed?
    if (transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return ANYRTC_CODE_SUCCESS;
    }

    // Stop ICE checklist (if running)
    if (trice_checklist_isrunning(transport->gatherer->ice)) {
        trice_checklist_stop(transport->gatherer->ice);
    }

    // TODO: Remove remote candidates, role, username fragment and password from rew

    // TODO: Remove from RTCICETransportController (once we have it)

    return ANYRTC_CODE_SUCCESS;
}

/*
 * Get the current ICE role of the ICE transport.
 * Return `ANYRTC_CODE_NO_VALUE` code in case the ICE role has not been
 * determined yet.
 */
enum anyrtc_code anyrtc_ice_transport_get_role(
        enum anyrtc_ice_role* const rolep, // de-referenced
        struct anyrtc_ice_transport* const transport
) {
    enum trice_role re_role;
    enum anyrtc_code error;
    enum anyrtc_ice_role role;

    // Check arguments
    if (!rolep || !transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Get libre role from ICE instance
    error = anyrtc_translate_re_code(trice_get_role(transport->gatherer->ice, &re_role));
    if (error) {
        return error;
    }

    // Translate role
    error = anyrtc_translate_re_trice_role(&role, re_role);
    if (error) {
        return error;
    }

    // Unknown?
    if (re_role == ANYRTC_ICE_ROLE_UNKNOWN) {
        return ANYRTC_CODE_NO_VALUE;
    } else {
        // Set pointer
        *rolep = role;
        return ANYRTC_CODE_SUCCESS;
    }
}

/*
 * Add a remote candidate ot the ICE transport.
 * Note: 'candidate' must be NULL to inform the transport that the
 * remote site finished gathering.
 */
enum anyrtc_code anyrtc_ice_transport_add_remote_candidate(
        struct anyrtc_ice_transport* const transport,
        struct anyrtc_ice_candidate* candidate // nullable
) {
    struct ice_rcand* re_candidate = NULL;
    enum anyrtc_code error;
    char* ip = NULL;
    uint16_t port;
    struct sa address;
    int af;
    enum anyrtc_ice_protocol protocol;
    char* foundation = NULL;
    uint32_t priority;
    enum anyrtc_ice_candidate_type type;
    enum anyrtc_ice_tcp_candidate_type tcp_type;
    char* related_address = NULL;

    // Check arguments
    if (!transport) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Check ICE transport state
    if (transport->state == ANYRTC_ICE_TRANSPORT_CLOSED) {
        return ANYRTC_CODE_INVALID_STATE;
    }

    // Remote site completed gathering?
    if (!candidate) {
        DEBUG_PRINTF("Remote site gathering complete\n%H", trice_debug, transport->gatherer->ice);
        return ANYRTC_CODE_SUCCESS;
    }

    // Get IP and port
    error = anyrtc_ice_candidate_get_ip(candidate, &ip);
    if (error) {
        goto out;
    }
    error = anyrtc_ice_candidate_get_port(candidate, &port);
    if (error) {
        goto out;
    }
    error = anyrtc_translate_re_code(sa_set_str(&address, ip, port));
    if (error) {
        goto out;
    }

    // Skip IPv4, IPv6 if requested
    // TODO: Get config from struct
    af = sa_af(&address);
    if (!anyrtc_default_config.ipv6_enable && af == AF_INET6
            || !anyrtc_default_config.ipv4_enable && af == AF_INET) {
        DEBUG_PRINTF("Skipping remote candidate due to IP version: %J\n", &address);
        goto out;
    }

    // Get protocol
    error = anyrtc_ice_candidate_get_protocol(candidate, &protocol);
    if (error) {
        goto out;
    }

    // Skip UDP/TCP if requested
    // TODO: Get config from struct
    if (!anyrtc_default_config.udp_enable && protocol == ANYRTC_ICE_PROTOCOL_UDP
            || !anyrtc_default_config.tcp_enable && protocol == ANYRTC_ICE_PROTOCOL_TCP) {
        DEBUG_PRINTF("Skipping remote candidate due to protocol: %J\n", &address);
        goto out;
    }

    // Get necessary vars
    error = anyrtc_ice_candidate_get_foundation(candidate, &foundation);
    if (error) {
        goto out;
    }
    error = anyrtc_ice_candidate_get_protocol(candidate, &protocol);
    if (error) {
        goto out;
    }
    error = anyrtc_ice_candidate_get_priority(candidate, &priority);
    if (error) {
        goto out;
    }
    error = anyrtc_ice_candidate_get_type(candidate, &type);
    if (error) {
        goto out;
    }
    error = anyrtc_ice_candidate_get_tcp_type(candidate, &tcp_type);
    switch (error) {
        case ANYRTC_CODE_SUCCESS:
            break;
        case ANYRTC_CODE_NO_VALUE:
            // Doesn't matter what we choose here, protocol is not TCP anyway
            tcp_type = ANYRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
            break;
        default:
            goto out;
    }

    // Add remote candidate
    // TODO: Set correct component ID
    error = anyrtc_translate_re_code(trice_rcand_add(
            &re_candidate, transport->gatherer->ice, 1, foundation,
            anyrtc_translate_ice_protocol(protocol), priority, &address,
            anyrtc_translate_ice_candidate_type(type),
            anyrtc_translate_ice_tcp_candidate_type(tcp_type)));
    if (error) {
        goto out;
    }

    // Set related address (if any)
    error = anyrtc_ice_candidate_get_related_address(candidate, &related_address);
    if (!error) {
        error = anyrtc_ice_candidate_get_related_port(candidate, &port);
        if (!error) {
            error = anyrtc_translate_re_code(sa_set_str(
                    &re_candidate->attr.rel_addr, related_address, port));
            if (error) {
                goto out;
            }
        }
    }
    if (error != ANYRTC_CODE_NO_VALUE) {
        goto out;
    }

    // Done
    DEBUG_PRINTF("Added remote candidate: %J\n", &address);
    error = ANYRTC_CODE_SUCCESS;

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
enum anyrtc_code anyrtc_ice_transport_set_remote_candidates(
        struct anyrtc_ice_transport* const transport,
        struct anyrtc_ice_candidate* const candidates[], // referenced (each item)
        size_t const n_candidates
) {
    // TODO: Implement
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
