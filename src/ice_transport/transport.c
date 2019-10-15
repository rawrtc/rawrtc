#include "transport.h"
#include "../dtls_transport/transport.h"
#include "../ice_candidate/candidate.h"
#include "../ice_candidate/helper.h"
#include "../ice_gatherer/gatherer.h"
#include "../ice_parameters/parameters.h"
#include "../main/config.h"
#include <rawrtc/config.h>
#include <rawrtc/ice_candidate.h>
#include <rawrtc/ice_gatherer.h>
#include <rawrtc/ice_transport.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>
#include <rew.h>

#define DEBUG_MODULE "ice-transport"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * Destructor for an existing ICE transport.
 */
static void rawrtc_ice_transport_destroy(void* arg) {
    struct rawrtc_ice_transport* const transport = arg;

    // Stop transport
    // TODO: Check effects in case transport has been destroyed due to error in create
    rawrtc_ice_transport_stop(transport);

    // Un-reference
    mem_deref(transport->stun_client);
    mem_deref(transport->remote_parameters);
    mem_deref(transport->gatherer);
}

/*
 * Create a new ICE transport.
 * `*transportp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_transport_create(
    struct rawrtc_ice_transport** const transportp,  // de-referenced
    struct rawrtc_ice_gatherer* const gatherer,  // referenced, nullable
    rawrtc_ice_transport_state_change_handler const state_change_handler,  // nullable
    rawrtc_ice_transport_candidate_pair_change_handler const
        candidate_pair_change_handler,  // nullable
    void* const arg  // nullable
) {
    struct rawrtc_ice_transport* transport;
    struct stun_conf stun_config = {
        // TODO: Make this configurable!
        .rto = 100,  // 100ms
        .rc = 7,  // Send at: 0ms, 100ms, 300ms, 700ms, 1500ms, 3100ms, 6300ms
        .rm = 60,  // Additional wait: 60*100 -> 6000ms
        .ti = 12300,  // Timeout after: 12300ms
        .tos = 0x00,
    };
    enum rawrtc_code error;

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
    transport->state = RAWRTC_ICE_TRANSPORT_STATE_NEW;  // TODO: Raise state (delayed)?
    transport->gatherer = mem_ref(gatherer);
    transport->state_change_handler = state_change_handler;
    transport->candidate_pair_change_handler = candidate_pair_change_handler;
    transport->arg = arg;
    transport->remote_end_of_candidates = false;

    // Create STUN client
    error = rawrtc_error_to_code(stun_alloc(&transport->stun_client, &stun_config, NULL, NULL));
    if (error) {
        goto out;
    }

out:
    if (error) {
        mem_deref(transport);
    } else {
        // Set pointer
        *transportp = transport;
    }
    return error;
}

/*
 * Change the state of the ICE transport.
 * Will call the corresponding handler.
 */
static void set_state(
    struct rawrtc_ice_transport* const transport, enum rawrtc_ice_transport_state const state) {
    // Set state
    transport->state = state;

    // Call handler (if any)
    if (transport->state_change_handler) {
        transport->state_change_handler(state, transport->arg);
    }
}

/*
 * Check if the ICE checklist process is complete.
 */
static void check_ice_checklist_complete(
    struct rawrtc_ice_transport* const transport  // not checked
) {
    struct trice* const ice = transport->gatherer->ice;

    // Completed all candidate pairs?
    if (trice_checklist_iscompleted(ice)) {
        struct le;

        DEBUG_INFO("Checklist completed\n");
        DEBUG_PRINTF("%H", trice_debug, ice);

        // Stop the checklist
        trice_checklist_stop(ice);

        // Remove STUN and TURN sessions from local candidate helpers since the keep-alive
        // mechanism now moves over to the peers themselves.
        list_apply(
            &transport->gatherer->local_candidates, true,
            rawrtc_candidate_helper_remove_stun_sessions_handler, NULL);

        // Start keep-alive for active candidate pairs
        // TODO: Implement!
        //        start_keepalive(transport);

        // Do we have one candidate pair that succeeded?
        if (!list_isempty(trice_validl(ice))) {
            // Have we received the remote end-of-candidates indication?
            if (transport->remote_end_of_candidates) {
                DEBUG_INFO("ICE connection completed\n");
                set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_COMPLETED);
            }
        } else {
            // No, transition to failed
            DEBUG_INFO("ICE connection failed\n");
            set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_FAILED);
        }
    }
}

/*
 * ICE connection established callback.
 */
static void ice_established_handler(
    struct ice_candpair* candidate_pair, struct stun_msg const* message, void* arg) {
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

    // Ignore if completed or failed
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_COMPLETED ||
        transport->state == RAWRTC_ICE_TRANSPORT_STATE_FAILED) {
        return;
    }

    // Offer candidate pair to DTLS transport (if any)
    // TODO: Offer to whatever transport lays above so we are SRTP/QUIC compatible
    if (transport->dtls_transport) {
        error = rawrtc_dtls_transport_add_candidate_pair(transport->dtls_transport, candidate_pair);
        if (error) {
            DEBUG_WARNING(
                "DTLS transport could not attach to candidate pair, reason: %s\n",
                rawrtc_code_to_str(error));

            // Important: Removing a candidate pair can lead to segfaults due to STUN transaction
            //            timers looking up the pair. Don't do it!
        }
    }

    // TODO: Call candidate_pair_change_handler (?)

    // ICE checklist process complete?
    check_ice_checklist_complete(transport);
}

/*
 * ICE connection failed callback.
 */
static void ice_failed_handler(
    int err, uint16_t stun_code, struct ice_candpair* candidate_pair, void* arg) {
    struct rawrtc_ice_transport* const transport = arg;
    (void) err;
    (void) stun_code;
    (void) candidate_pair;

    DEBUG_PRINTF(
        "Candidate pair failed: %H (%m %" PRIu16 ")\n", trice_candpair_debug, candidate_pair, err,
        stun_code);

    // Ignore if closed
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED) {
        return;
    }

    // Ignore if completed or failed
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_COMPLETED ||
        transport->state == RAWRTC_ICE_TRANSPORT_STATE_FAILED) {
        return;
    }

    // ICE checklist process complete?
    check_ice_checklist_complete(transport);

    // Important: Removing the failed candidate pair can lead to segfaults due to STUN transaction
    //            timers looking up the pair. Don't do it!
}

/*
 * Start the ICE transport.
 * TODO https://github.com/w3c/ortc/issues/607
 */
enum rawrtc_code rawrtc_ice_transport_start(
    struct rawrtc_ice_transport* const transport,
    struct rawrtc_ice_gatherer* const gatherer,  // referenced
    struct rawrtc_ice_parameters* const remote_parameters,  // referenced
    enum rawrtc_ice_role const role) {
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
        error = rawrtc_error_to_code(
            trice_set_remote_ufrag(transport->gatherer->ice, remote_parameters->username_fragment));
        if (error) {
            return error;
        }
        error = rawrtc_error_to_code(
            trice_set_remote_pwd(transport->gatherer->ice, remote_parameters->password));
        if (error) {
            return error;
        }

        // Replace
        mem_deref(transport->remote_parameters);
        transport->remote_parameters = mem_ref(remote_parameters);
    }

    // Set state to checking
    // TODO: Get more states from trice
    set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_CHECKING);

    // Start checklist
    // TODO: Get config from struct
    DEBUG_INFO("Starting checklist due to start event\n");
    error = rawrtc_error_to_code(trice_checklist_start(
        transport->gatherer->ice, transport->stun_client, rawrtc_default_config.pacing_interval,
        ice_established_handler, ice_failed_handler, transport));
    if (error) {
        return error;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Stop and close the ICE transport.
 */
enum rawrtc_code rawrtc_ice_transport_stop(struct rawrtc_ice_transport* const transport) {
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
 * Add a remote candidate ot the ICE transport.
 * Note: 'candidate' must be NULL to inform the transport that the
 * remote site finished gathering.
 */
enum rawrtc_code rawrtc_ice_transport_add_remote_candidate(
    struct rawrtc_ice_transport* const transport,
    struct rawrtc_ice_candidate* candidate  // nullable
) {
    struct ice_rcand* re_candidate = NULL;
    enum rawrtc_code error;
    char* ip = NULL;
    uint16_t port;
    struct sa address = {0};
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
    if (transport->state == RAWRTC_ICE_TRANSPORT_STATE_CLOSED ||
        transport->state == RAWRTC_ICE_TRANSPORT_STATE_FAILED ||
        transport->state == RAWRTC_ICE_TRANSPORT_STATE_COMPLETED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Remote site completed gathering?
    if (!candidate) {
        if (!transport->remote_end_of_candidates) {
            DEBUG_PRINTF(
                "Remote site gathering complete\n%H", trice_debug, transport->gatherer->ice);

            // Transition to 'complete' if the checklist is done
            // Note: 'completed' and 'failed' states are covered in checks above
            if (transport->state != RAWRTC_ICE_TRANSPORT_STATE_NEW &&
                !trice_checklist_isrunning(transport->gatherer->ice)) {
                set_state(transport, RAWRTC_ICE_TRANSPORT_STATE_COMPLETED);
            }

            // Mark that we've received end-of-candidates
            transport->remote_end_of_candidates = true;
        }

        // Done
        return RAWRTC_CODE_SUCCESS;
    }

    // New remote candidate after end-of-candidates indication?
    if (transport->remote_end_of_candidates) {
        DEBUG_NOTICE("Tried to add a remote candidate after end-of-candidates\n");
        return RAWRTC_CODE_INVALID_STATE;
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
    if ((!rawrtc_default_config.ipv6_enable && af == AF_INET6) ||
        (!rawrtc_default_config.ipv4_enable && af == AF_INET)) {
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
    if ((!rawrtc_default_config.udp_enable && protocol == RAWRTC_ICE_PROTOCOL_UDP) ||
        (!rawrtc_default_config.tcp_enable && protocol == RAWRTC_ICE_PROTOCOL_TCP)) {
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
            error = rawrtc_error_to_code(
                sa_set_str(&re_candidate->attr.rel_addr, related_address, port));
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

    // Start checklist (if not new, not started and not completed or failed)
    // TODO: Get config from struct
    if (transport->state != RAWRTC_ICE_TRANSPORT_STATE_NEW &&
        transport->state != RAWRTC_ICE_TRANSPORT_STATE_COMPLETED &&
        transport->state != RAWRTC_ICE_TRANSPORT_STATE_FAILED &&
        !trice_checklist_isrunning(transport->gatherer->ice)) {
        DEBUG_INFO("Starting checklist due to new remote candidate\n");
        error = rawrtc_error_to_code(trice_checklist_start(
            transport->gatherer->ice, transport->stun_client, rawrtc_default_config.pacing_interval,
            ice_established_handler, ice_failed_handler, transport));
        if (error) {
            DEBUG_WARNING("Could not start checklist, reason: %s\n", rawrtc_code_to_str(error));
            goto out;
        }
    }

out:
    if (error) {
        mem_deref(re_candidate);  // TODO: Not entirely sure about that
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
    struct rawrtc_ice_candidate* const candidates[],  // referenced (each item)
    size_t const n_candidates) {
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
