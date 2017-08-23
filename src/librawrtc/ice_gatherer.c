#include <sys/socket.h> // AF_INET, AF_INET6
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <string.h> // memcpy
#include <rawrtc.h>
#include "ice_gatherer.h"
#include "config.h"
#include "utils.h"
#include "packet_trace.h"
#include "ice_server.h"
#include "ice_candidate.h"
#include "message_buffer.h"
#include "candidate_helper.h"

#define DEBUG_MODULE "ice-gatherer"
#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include "debug.h"

/*
 * Get the corresponding address family name for an DNS type.
 */
static char const * const dns_type_to_address_family_name(
        uint_fast16_t const dns_type
) {
    switch (dns_type) {
        case DNS_TYPE_A:
            return "IPv4";
        case DNS_TYPE_AAAA:
            return "IPv6";
        default:
            return "???";
    }
}

/*
 * Destroy all ICE server URL DNS contexts.
 */
static void gather_options_destroy_url_dns_contexts(
        struct rawrtc_ice_gather_options* const options // not checked
) {
    struct le* le;
    for (le = list_head(&options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;

        // Destroy URL DNS contexts
        enum rawrtc_code const error = rawrtc_ice_server_destroy_url_dns_contexts(server);
        if (error) {
            DEBUG_WARNING("Could not destroy DNS contexts of ICE server URLs\n");
            // Continue - not considered critical
        }
    }
}

static void rawrtc_ice_gather_options_destroy(
        void* arg
) {
    struct rawrtc_ice_gather_options* const options = arg;

    // Un-reference
    list_flush(&options->ice_servers);
}

/*
 * Create a new ICE gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_create(
        struct rawrtc_ice_gather_options** const optionsp, // de-referenced
        enum rawrtc_ice_gather_policy const gather_policy
) {
    struct rawrtc_ice_gather_options* options;

    // Check arguments
    if (!optionsp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    options = mem_zalloc(sizeof(*options), rawrtc_ice_gather_options_destroy);
    if (!options) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    options->gather_policy = gather_policy;
    list_init(&options->ice_servers);

    // Set pointer and return
    *optionsp = options;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Add an ICE server to the gather options.
 */
enum rawrtc_code rawrtc_ice_gather_options_add_server(
        struct rawrtc_ice_gather_options* const options,
        struct rawrtc_config* const config, // nullable
        char* const * const urls, // copied
        size_t const n_urls,
        char* const username, // nullable, copied
        char* const credential, // nullable, copied
        enum rawrtc_ice_credential_type const credential_type
) {
    struct rawrtc_ice_server* server;
    enum rawrtc_code error;

    // Check arguments
    if (!options || !urls) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Ensure there are less than 2^8 servers
    if (list_count(&options->ice_servers) == UINT8_MAX) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Create ICE server
    error = rawrtc_ice_server_create(
            &server, config ? config : &rawrtc_default_config, urls, n_urls, username, credential,
            credential_type);
    if (error) {
        return error;
    }

    // Add to options
    list_append(&options->ice_servers, &server->le, server);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Print debug information for the ICE gather options.
 */
static int ice_gather_options_debug(
        struct re_printf* const pf,
        struct rawrtc_ice_gather_options const* const options
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!options) {
        return 0;
    }

    err |= re_hprintf(pf, "----- ICE Gather Options <%p> -----\n", options);

    // Gather policy
    err |= re_hprintf(pf, "  gather_policy=%s\n",
                      rawrtc_ice_gather_policy_to_str(options->gather_policy));

    // ICE servers
    for (le = list_head(&options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;
        err |= re_hprintf(pf, "%H", rawrtc_ice_server_debug, server);
    }

    // Done
    return err;
}

/*
 * Get the corresponding name for an ICE gatherer state.
 */
char const * const rawrtc_ice_gatherer_state_to_name(
        enum rawrtc_ice_gatherer_state const state
) {
    switch (state) {
        case RAWRTC_ICE_GATHERER_NEW:
            return "new";
        case RAWRTC_ICE_GATHERER_GATHERING:
            return "gathering";
        case RAWRTC_ICE_GATHERER_COMPLETE:
            return "complete";
        case RAWRTC_ICE_GATHERER_CLOSED:
            return "closed";
        default:
            return "???";
    }
}

/*
 * Destructor for an existing ICE gatherer.
 */
static void rawrtc_ice_gatherer_destroy(
        void* arg
) {
    struct rawrtc_ice_gatherer* const gatherer = arg;

    // Close gatherer
    // TODO: Check effects in case transport has been destroyed due to error in create
    rawrtc_ice_gatherer_close(gatherer);

    // Un-reference
    mem_deref(gatherer->dns_client);
    mem_deref(gatherer->ice);
    list_flush(&gatherer->local_candidates);
    list_flush(&gatherer->buffered_messages);
    mem_deref(gatherer->options);
    if (gatherer->config != &rawrtc_default_config) {
        mem_deref(gatherer->config);
    }

    // Close trace file (if any): TURN
    if (gatherer->trace_handle_turn) {
        enum rawrtc_code const error = rawrtc_packet_trace_handle_close(
                gatherer->trace_handle_turn);
        if (error) {
            DEBUG_NOTICE("Could close TURN packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Close trace file (if any): STUN
    if (gatherer->trace_handle_stun) {
        enum rawrtc_code const error = rawrtc_packet_trace_handle_close(
                gatherer->trace_handle_stun);
        if (error) {
            DEBUG_NOTICE("Could close STUN packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Close trace file (if any): ICE
    if (gatherer->trace_handle_ice) {
        enum rawrtc_code const error = rawrtc_packet_trace_handle_close(
                gatherer->trace_handle_ice);
        if (error) {
            DEBUG_NOTICE("Could close ICE packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }
}

/*
 * Create a new ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_create(
        struct rawrtc_ice_gatherer** const gathererp, // de-referenced
        struct rawrtc_config* const config, // referenced, nullable
        struct rawrtc_ice_gather_options* const options, // referenced
        rawrtc_ice_gatherer_state_change_handler* const state_change_handler, // nullable
        rawrtc_ice_gatherer_error_handler* const error_handler, // nullable
        rawrtc_ice_gatherer_local_candidate_handler* const local_candidate_handler, // nullable
        void* const arg // nullable
) {
    struct rawrtc_ice_gatherer* gatherer;
    enum rawrtc_log_level log_level;
    int err;
    struct sa dns_servers[RAWRTC_ICE_GATHERER_DNS_SERVERS] = {{{{0}}}};
    uint32_t n_dns_servers = ARRAY_SIZE(dns_servers);
    uint32_t i;

    // Check arguments
    if (!gathererp || !options) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    gatherer = mem_zalloc(sizeof(*gatherer), rawrtc_ice_gatherer_destroy);
    if (!gatherer) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    gatherer->state = RAWRTC_ICE_GATHERER_NEW; // TODO: Raise state (delayed)?
    if (!config || config == &rawrtc_default_config) {
        gatherer->config = &rawrtc_default_config;
    } else {
        gatherer->config = mem_ref(config);
    }
    gatherer->options = mem_ref(options);
    gatherer->state_change_handler = state_change_handler;
    gatherer->error_handler = error_handler;
    gatherer->local_candidate_handler = local_candidate_handler;
    gatherer->arg = arg;
    list_init(&gatherer->buffered_messages);
    list_init(&gatherer->local_candidates);

    // Generate random username fragment and password for ICE
    rand_str(gatherer->ice_username_fragment, sizeof(gatherer->ice_username_fragment));
    rand_str(gatherer->ice_password, sizeof(gatherer->ice_password));

    // Create trace files (if requested)
    if (gatherer->config->debug.packet_trace_path) {
        enum rawrtc_code error;

        // Layer: ICE
        error = rawrtc_packet_trace_handle_open(
                &gatherer->trace_handle_ice, gatherer, gatherer->config, RAWRTC_LAYER_ICE_HOST);
        if (error) {
            DEBUG_NOTICE("Could open ICE packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }

        // Layer: STUN
        error = rawrtc_packet_trace_handle_open(
                &gatherer->trace_handle_stun, gatherer, gatherer->config, RAWRTC_LAYER_STUN);
        if (error) {
            DEBUG_NOTICE("Could open STUN packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }

        // Layer: TURN
        error = rawrtc_packet_trace_handle_open(
                &gatherer->trace_handle_turn, gatherer, gatherer->config, RAWRTC_LAYER_TURN);
        if (error) {
            DEBUG_NOTICE("Could open TURN packet trace handle, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Set ICE configuration and create trice instance
    // TODO: Update this when adding more log levels to config
    log_level = gatherer->config->debug.log_level;
    gatherer->ice_config.debug = log_level == RAWRTC_LOG_LEVEL_ALL_TEMP ? true : false;
    gatherer->ice_config.trace = log_level == RAWRTC_LOG_LEVEL_ALL_TEMP ? true : false;
    gatherer->ice_config.ansi = gatherer->config->debug.log_colors_enable;
    gatherer->ice_config.enable_prflx = gatherer->config->ice.prflx_enable;
    err = trice_alloc(
            &gatherer->ice, &gatherer->ice_config, ICE_ROLE_UNKNOWN,
            gatherer->ice_username_fragment, gatherer->ice_password);
    if (err) {
        DEBUG_WARNING("Unable to create trickle ICE instance, reason: %m\n", err);
        goto out;
    }

    // Get local DNS servers
    err = dns_srv_get(NULL, 0, dns_servers, &n_dns_servers);
    if (err) {
        DEBUG_WARNING("Unable to retrieve local DNS servers, reason: %m\n", err);
        goto out;
    }

    // Print local DNS servers
    if (n_dns_servers == 0) {
        DEBUG_NOTICE("No DNS servers found\n");
    }
    for (i = 0; i < n_dns_servers; ++i) {
        DEBUG_PRINTF("DNS server: %j\n", &dns_servers[i]);
    }

    // Create DNS client (for resolving ICE server IPs)
    err = dnsc_alloc(&gatherer->dns_client, NULL, dns_servers, n_dns_servers);
    if (err) {
        DEBUG_WARNING("Unable to create DNS client instance, reason: %m\n", err);
        goto out;
    }

    // Done
    DEBUG_PRINTF("ICE gatherer created:\n%H", rawrtc_ice_gatherer_debug, gatherer);

out:
    if (err) {
        mem_deref(gatherer);
    } else {
        // Set pointer
        *gathererp = gatherer;
    }
    return rawrtc_error_to_code(err);
}

/*
 * Change the state of the ICE gatherer.
 * Will call the corresponding handler.
 * TODO: https://github.com/w3c/ortc/issues/606
 */
static void set_state(
        struct rawrtc_ice_gatherer* const gatherer,
        enum rawrtc_ice_gatherer_state const state
) {
    // Set state
    gatherer->state = state;
    DEBUG_PRINTF("ICE gatherer:\n%H", rawrtc_ice_gatherer_debug, gatherer);

    // Call handler (if any)
    if (gatherer->state_change_handler) {
        gatherer->state_change_handler(state, gatherer->arg);
    }
}

/*
 * Close the ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_close(
        struct rawrtc_ice_gatherer* const gatherer
) {
    enum rawrtc_code error;

    // Check arguments
    if (!gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Already closed?
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // TODO: Stop ICE transport

    // Remove STUN and TURN sessions from local candidate helpers
    // Note: Needed to purge remaining references to the gatherer so it can be free'd.
    error = rawrtc_candidate_helper_remove_sessions(&gatherer->local_candidates);
    if (error) {
        DEBUG_WARNING("Unable to remove STUN/TURN sessions, reason: %s\n",
                      rawrtc_code_to_str(error));
        // Note: Not considered critical
    }

    // Flush local candidate helpers
    list_flush(&gatherer->local_candidates);

    // Remove ICE server URL DNS context's
    // TODO: Does this stop the resolving process?
    gather_options_destroy_url_dns_contexts(gatherer->options);

    // Stop ICE checklist (if running)
    trice_checklist_stop(gatherer->ice);

    // Remove ICE agent
    gatherer->ice = mem_deref(gatherer->ice);

    // Set state to closed and return
    set_state(gatherer, RAWRTC_ICE_GATHERER_CLOSED);
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Handle received UDP messages.
 */
static bool udp_receive_handler(
        struct sa * source,
        struct mbuf* buffer,
        void* arg
) {
    struct rawrtc_ice_gatherer* const gatherer = arg;
    enum rawrtc_code error;

    // Allocate context and copy source address
    void* const context = mem_zalloc(sizeof(*source), NULL);
    if (!context) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }
    memcpy(context, source, sizeof(*source));

    // Buffer message
    error = rawrtc_message_buffer_append(&gatherer->buffered_messages, buffer, context);
    if (error) {
        goto out;
    }

    // Done
    DEBUG_PRINTF("Buffered UDP packet of size %zu\n", mbuf_get_left(buffer));

out:
    if (error) {
        DEBUG_WARNING("Could not buffer UDP packet, reason: %s\n", rawrtc_code_to_str(error));
    }

    // Un-reference
    mem_deref(context);

    // Handled
    return true;
}

/*
 * Announce a local candidate.
 */
static enum rawrtc_code announce_candidate(
        struct rawrtc_ice_gatherer* const gatherer, // not checked
        struct ice_lcand* const re_candidate, // nullable
        char const* const url // nullable
) {
    enum rawrtc_code error;

    // Create ICE candidate
    if (gatherer->local_candidate_handler) {
        struct rawrtc_ice_candidate* ice_candidate = NULL;

        // Create ICE candidate
        if (re_candidate) {
            error = rawrtc_ice_candidate_create_from_local_candidate(&ice_candidate, re_candidate);
            if (error) {
                return error;
            }
        }

        // Call candidate handler and un-reference
        gatherer->local_candidate_handler(ice_candidate, url, gatherer->arg);
        mem_deref(ice_candidate);
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Check if the gathering process is complete.
 */
static void check_gathering_complete(
        struct rawrtc_ice_gatherer* const gatherer // not checked
) {
    struct le* le;
    enum rawrtc_code error;

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return;
    }

    // Ensure no DNS queries are in flight
    for (le = list_head(&gatherer->options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;
        struct rawrtc_ice_server_url* url;
        bool pending;

        // Check for pending DNS queries
        error = rawrtc_ice_server_dns_queries_pending(&pending, &url, server);
        if (error) {
            DEBUG_WARNING("Could not check for pending DNS queries on ICE server\n");
            // Continue - not considered critical
            continue;
        }
        if (pending) {
            // Nope, not complete
            DEBUG_PRINTF("Gathering still in progress, pending DNS record queries (%s)\n",
                         url->url);
            return;
        }
    }

    // Ensure every local candidate has no pending srflx/relay candidates
    for (le = list_head(&gatherer->local_candidates); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate = le->data;

        // Check counters
        if (candidate->srflx_pending_count > 0 || candidate->relay_pending_count > 0) {
            // Nope
            DEBUG_PRINTF(
                    "Gathering still in progress at candidate %j, #srflx=%"PRIuFAST8", #relay=%"
                    PRIuFAST8"\n", &candidate->candidate->attr.addr,
                    candidate->srflx_pending_count, candidate->relay_pending_count);
            return;
        }
    }

    // Announce candidate gathering complete
    error = announce_candidate(gatherer, NULL, NULL);
    if (error) {
        DEBUG_WARNING("Could not announce end-of-candidates, reason: %s\n",
                      rawrtc_code_to_str(error));

        // This should never happen, so close on failure
        rawrtc_ice_gatherer_close(gatherer);
        return;
    }

    // Update state & done
    DEBUG_PRINTF("Gathering complete:\n%H", trice_debug, gatherer->ice);
    set_state(gatherer, RAWRTC_ICE_GATHERER_COMPLETE);
}

/*
 * Find an existing local candidate.
 * TODO: This should probably be moved into a PR towards rew
 */
static struct ice_lcand* find_candidate(
        struct trice* const ice,
        enum ice_cand_type type, // set to -1 if it should not be checked
        unsigned const component_id, // set to 0 if it should not be checked
        int const protocol,
        struct sa const * const address, // nullable
        enum sa_flag const address_flag,
        struct sa const * base_address, // nullable
        enum sa_flag const base_address_flags
) {
    struct le* le;

    // Check arguments
    if (!ice) {
        return NULL;
    }

    // If base address and address have an identical IP, ignore the base address and the type
    if (address && base_address && sa_cmp(address, base_address, SA_ADDR)) {
        base_address = NULL;
        type = (enum ice_cand_type) -1;
    }

    for (le = list_head(trice_lcandl(ice)); le != NULL; le = le->next) {
        struct ice_lcand* candidate = le->data;

        // Check type (if requested)
        if (type != (enum ice_cand_type) -1 && type != candidate->attr.type) {
            continue;
        }

        // Check component id (if requested)
        if (component_id && candidate->attr.compid != component_id) {
            continue;
        }

        // Check protocol
        if (candidate->attr.proto != protocol) {
            continue;
        }

        // Check address
        if (address && !sa_cmp(&candidate->attr.addr, address, address_flag)) {
            continue;
        }

        // Check base address
        if (base_address && !sa_cmp(&candidate->base_addr, base_address, base_address_flags)) {
            continue;
        }

        // Found
        return candidate;
    }

    // Not found
    return NULL;
}

/*
 * Handle TURN permission response.
 */
static void turn_permission_handler(
        void* arg
) {
    struct ice_rcand* const remote_candidate = arg;
    DEBUG_PRINTF("Added TURN permission for remote peer %J\n", &remote_candidate->attr.addr);
}

/*
 * Add TURN permission for a local/remote candidate combination on a single TURN session.
 */
static enum rawrtc_code add_turn_permission(
        struct rawrtc_candidate_helper_turn_session* const session, // not checked
        struct ice_lcand* const local_candidate, // not checked
        struct ice_rcand* const remote_candidate // not checked
) {
    // Ensure they have the same component id, address family and protocol
    if (local_candidate->attr.compid != remote_candidate->attr.compid
        || sa_af(&local_candidate->attr.addr) != sa_af(&remote_candidate->attr.addr)
        || local_candidate->attr.proto != remote_candidate->attr.proto) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Add permission
    int const err = turnc_add_perm(
            session->turn_client, &remote_candidate->attr.addr, turn_permission_handler,
            remote_candidate);
    if (err) {
        DEBUG_WARNING("Unable to add TURN permission for pair %J <-> %J, reason: %m\n",
                      &local_candidate->attr.addr, &remote_candidate->attr.addr, err);
    } else {
        DEBUG_PRINTF("Trying to add TURN permission for pair %J <-> %J\n",
                     &local_candidate->attr.addr, &remote_candidate->attr.addr);
    }

    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Add TURN permission for all known remote candidates on a single TURN session
 * created for a specific candidate.
 */
static void add_turn_permission_on_known_remote_candidates(
        struct rawrtc_ice_gatherer* const gatherer, // not checked
        struct rawrtc_candidate_helper_turn_session* const session // not checked
) {
    struct le* le;
    for (le = list_head(trice_rcandl(gatherer->ice)); le != NULL; le = le->next) {
        struct ice_rcand* const remote_candidate = le->data;

        // Add permission
        // Note: Return code not handled as not considered critical
        add_turn_permission(session, session->candidate_helper->candidate, remote_candidate);
    }
}

/*
 * Handle TURN client allocation.
 */
static void turn_client_handler(
        int err,
        uint16_t scode,
        char const* reason,
        struct sa const* relay_address, // not checked
        struct sa const* mapped_address, // not checked
        struct stun_msg const* message, // not checked
        void* arg
) {
    struct rawrtc_candidate_helper_turn_session* const session = arg;
    struct rawrtc_candidate_helper* const candidate = session->candidate_helper;
    struct rawrtc_ice_gatherer* const gatherer = candidate->gatherer;
    bool remove_session = true;
    uint16_t method;
    struct ice_lcand* const re_candidate = candidate->candidate;
    uint32_t priority;
    struct ice_lcand* relay_candidate;
    enum rawrtc_code error;

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        goto out;
    }

    // Error?
    if (err || scode) {
        DEBUG_NOTICE("TURN allocation failed, reason: err=%m scode=%"PRIu16" %s\n",
                     err, scode, reason);
        goto out;
    }

    // Sanity-check
    method = stun_msg_method(message);
    if (method != STUN_METHOD_ALLOCATE) {
        DEBUG_WARNING("Unexpected method: %s\n", stun_method_name(method));
        goto out;
    }

    // Add relay candidate
    // TODO: Using the candidate's protocol, TCP type and component id correct?
    priority = rawrtc_ice_candidate_calculate_priority(
            ICE_CAND_TYPE_RELAY, re_candidate->attr.proto, sa_af(mapped_address),
            re_candidate->attr.tcptype);
    err = trice_lcand_add(
            &relay_candidate, gatherer->ice, re_candidate->attr.compid, re_candidate->attr.proto,
            priority, relay_address, relay_address, ICE_CAND_TYPE_RELAY, mapped_address,
            re_candidate->attr.tcptype, re_candidate->us, RAWRTC_LAYER_ICE_RELAY);
    if (err) {
        DEBUG_WARNING("Could not add relay candidate, reason: %m\n", err);
        goto out;
    }

    // Add relay candidate to TURN session
    error = rawrtc_candidate_helper_turn_session_add_candidate(session, relay_candidate);
    if (error) {
        DEBUG_WARNING("Could not add relay candidate to TURN session, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }
    DEBUG_PRINTF("Added %s relay candidate for interface mapped=%j, relay=%j (%s)\n",
                 net_proto2name(relay_candidate->attr.proto), mapped_address, relay_address,
                 session->url->url);

    // Use session
    remove_session = false;

    // Add TURN permission
    add_turn_permission_on_known_remote_candidates(gatherer, session);

    // Announce candidate to handler
    error = announce_candidate(gatherer, relay_candidate, session->url->url);
    if (error) {
        DEBUG_WARNING("Could not announce relay candidate, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

out:
    // Decrease counter & check if done gathering
    --candidate->relay_pending_count;
    check_gathering_complete(gatherer);

    // Remove session if requested
    if (remove_session) {
        mem_deref(session);
    }
}

/*
 * Gather relay candidates on an ICE server.
 */
static enum rawrtc_code gather_relay_candidates(
        struct rawrtc_candidate_helper* const candidate, // not checked
        struct sa* server_address, // not checked
        struct rawrtc_ice_server_url* const url, // not checked
        struct rawrtc_ice_server* const server // not checked
) {
    enum rawrtc_code error;
    struct ice_lcand* const re_candidate = candidate->candidate;
    enum rawrtc_ice_protocol protocol;
    enum rawrtc_ice_candidate_type type;
    char const* type_str;
    struct rawrtc_candidate_helper_turn_session* session = NULL;
    struct turnc* turn_client = NULL;

    // Check ICE server is enabled for TURN
    if (url->type != RAWRTC_ICE_SERVER_TYPE_TURN) {
        return RAWRTC_CODE_SUCCESS;
    }

    // TODO: Add IPv6 support (re doesn't support IPv6 TURN atm)
    if (sa_af(server_address) == AF_INET6 || (re_candidate->attr.proto == IPPROTO_UDP
                                              && sa_af(&re_candidate->attr.addr) == AF_INET6)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Get protocol
    error = rawrtc_ipproto_to_ice_protocol(&protocol, re_candidate->attr.proto);
    if (error) {
        goto out;
    }

    // Convert ICE candidate type
    error = rawrtc_ice_cand_type_to_ice_candidate_type(&type, re_candidate->attr.type);
    if (error) {
        goto out;
    }
    type_str = rawrtc_ice_candidate_type_to_str(type);
    (void) type_str;

    // Create TURN session
    error = rawrtc_candidate_helper_turn_session_create(&session, url);
    if (error) {
        goto out;
    }

    // Attach trace handler (if trace handle): TURN layer
    if (candidate->gatherer->trace_handle_turn) {
        error = rawrtc_candidate_helper_attach_packet_trace_handler(
                &candidate->udp_helper_trace_turn, candidate,
                candidate->gatherer->trace_handle_turn, RAWRTC_LAYER_TRACE_TURN);
        if (error) {
            DEBUG_NOTICE("Unable to attach TURN packet trace handler, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Create TURN client
    switch (protocol) {
        case RAWRTC_ICE_PROTOCOL_UDP:
            // Create client for UDP
            // TODO: What about UDP relay for TCP candidates?
            DEBUG_PRINTF("Creating TURN allocation for %s %s candidate %J using server %J (%s)\n",
                         net_proto2name(re_candidate->attr.proto), type_str,
                         &re_candidate->attr.addr, server_address, url->url);
            error = rawrtc_error_to_code(turnc_alloc(
                    &turn_client, (struct stun_conf*) &candidate->gatherer->config->stun,
                    IPPROTO_UDP, re_candidate->us, (int) RAWRTC_LAYER_TURN, server_address,
                    server->username, server->credential,
                    candidate->gatherer->config->turn.allocation_lifetime,
                    turn_client_handler, session));
            if (error) {
                goto out;
            }
            break;

        case RAWRTC_ICE_PROTOCOL_TCP:
            // TODO: Create client for TCP
            // TODO: What about TCP relay for UDP candidates?
            error = RAWRTC_CODE_NOT_IMPLEMENTED;
            goto out;
            break;

        default:
            error = RAWRTC_CODE_INVALID_ARGUMENT;
            goto out;
            break;
    }

    // Add the TURN session to the candidate
    error = rawrtc_candidate_helper_turn_session_add(session, candidate, turn_client);
    if (error) {
        goto out;
    }

    // Increase counter & done
    ++candidate->relay_pending_count;
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        DEBUG_WARNING("Could not create TURN allocation, reason: %s\n", rawrtc_code_to_str(error));
        mem_deref(session);
    }

    // Un-reference & done
    mem_deref(turn_client);
    return error;
}

/*
 * Handle gathered server reflexive candidate.
 */
static void reflexive_candidate_handler(
        int err,
        struct sa const* address, // not checked
        void* arg // not checked
) {
    struct rawrtc_candidate_helper_stun_session* const session = arg;
    struct rawrtc_candidate_helper* const candidate = session->candidate_helper;
    struct rawrtc_ice_gatherer* const gatherer = candidate->gatherer;
    bool remove_session = true;
    struct ice_lcand* const re_candidate = candidate->candidate;
    struct ice_lcand* re_other_candidate;
    uint32_t priority;
    struct ice_lcand* srflx_candidate;
    enum rawrtc_code error;

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        goto out;
    }

    // Error?
    if (err) {
        DEBUG_NOTICE("STUN request failed, reason: %m\n", err);
        goto out;
    }

    // Check if a local candidate with the same base and same attributes (apart from the port)
    // exists
    re_other_candidate = find_candidate(
            gatherer->ice, ICE_CAND_TYPE_SRFLX, re_candidate->attr.compid, re_candidate->attr.proto,
            address, SA_ADDR, &re_candidate->attr.addr, SA_ALL);
    if (re_other_candidate) {
        DEBUG_PRINTF("Ignoring server reflexive candidate with same base %J and public IP %j (%s)"
                     "\n", &re_candidate->attr.addr, address, session->url->url);
        goto out;
    }

    // Add server reflexive candidate
    // TODO: Using the candidate's protocol, TCP type and component id correct?
    priority = rawrtc_ice_candidate_calculate_priority(
            ICE_CAND_TYPE_SRFLX, re_candidate->attr.proto, sa_af(address),
            re_candidate->attr.tcptype);
    err = trice_lcand_add(
            &srflx_candidate, gatherer->ice, re_candidate->attr.compid, re_candidate->attr.proto,
            priority, address, &re_candidate->attr.addr, ICE_CAND_TYPE_SRFLX,
            &re_candidate->attr.addr, re_candidate->attr.tcptype, NULL, RAWRTC_LAYER_ICE_SRFLX);
    if (err) {
        DEBUG_WARNING("Could not add server reflexive candidate, reason: %m\n", err);
        goto out;
    }

    // Add srflx candidate to STUN session
    error = rawrtc_candidate_helper_stun_session_add_candidate(session, srflx_candidate);
    if (error) {
        DEBUG_WARNING("Could not add srflx candidate to TURN session, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }
    DEBUG_PRINTF("Added %s server reflexive candidate for interface %j (%s)\n",
                 net_proto2name(srflx_candidate->attr.proto), address, session->url->url);

    // Use session
    remove_session = false;

    // Announce candidate to handler
    error = announce_candidate(gatherer, srflx_candidate, session->url->url);
    if (error) {
        DEBUG_WARNING("Could not announce server reflexive candidate, reason: %s\n",
                      rawrtc_code_to_str(error));
        goto out;
    }

out:
    // Decrease counter & check if done gathering
    --candidate->srflx_pending_count;
    check_gathering_complete(gatherer);

    // Remove session if requested
    if (remove_session) {
        mem_deref(session);
    }
}

/*
 * Gather server reflexive candidates on an ICE server.
 */
static enum rawrtc_code gather_reflexive_candidates(
        struct rawrtc_candidate_helper* const candidate, // not checked
        struct sa* server_address, // not checked
        struct rawrtc_ice_server_url* const url // not checked
) {
    enum rawrtc_code error;
    struct ice_lcand* const re_candidate = candidate->candidate;
    enum rawrtc_ice_protocol protocol;
    enum rawrtc_ice_candidate_type type;
    char const* type_str;
    struct rawrtc_candidate_helper_stun_session* session = NULL;
    struct stun_keepalive* stun_keepalive = NULL;

    // Ensure the candidate's protocol matches the server address's protocol
    if (sa_af(&re_candidate->attr.addr) != sa_af(server_address)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Get protocol
    error = rawrtc_ipproto_to_ice_protocol(&protocol, re_candidate->attr.proto);
    if (error) {
        goto out;
    }

    // TODO: Code below only works with UDP - sorry!
    if (protocol != RAWRTC_ICE_PROTOCOL_UDP) {
        error = RAWRTC_CODE_NOT_IMPLEMENTED;
        goto out;
    }

    // Convert ICE candidate type
    error = rawrtc_ice_cand_type_to_ice_candidate_type(&type, re_candidate->attr.type);
    if (error) {
        goto out;
    }
    type_str = rawrtc_ice_candidate_type_to_str(type);
    (void) type_str;

    // TODO: Handle TCP/TLS/DTLS transports

    // Create STUN session
    error = rawrtc_candidate_helper_stun_session_create(&session, url);
    if (error) {
        goto out;
    }

    // Attach trace handler (if trace handle): STUN layer
    if (candidate->gatherer->trace_handle_stun) {
        error = rawrtc_candidate_helper_attach_packet_trace_handler(
                &candidate->udp_helper_trace_stun, candidate,
                candidate->gatherer->trace_handle_stun, RAWRTC_LAYER_TRACE_STUN);
        if (error) {
            DEBUG_NOTICE("Unable to attach STUN packet trace handler, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Create STUN keep-alive session
    // TODO: We're using the candidate's protocol which conflicts with the ICE server URL transport
    DEBUG_PRINTF("Creating STUN request for %s %s candidate %J using server %J (%s)\n",
                 net_proto2name(re_candidate->attr.proto), type_str, &re_candidate->attr.addr,
                 server_address, url->url);
    error = rawrtc_error_to_code(stun_keepalive_alloc(
            &stun_keepalive, re_candidate->attr.proto, re_candidate->us, RAWRTC_LAYER_STUN,
            server_address, (struct stun_conf*) &candidate->gatherer->config->stun,
            reflexive_candidate_handler, session));
    if (error) {
        goto out;
    }

    // Add the STUN session to the candidate
    error = rawrtc_candidate_helper_stun_session_add(session, candidate, stun_keepalive);
    if (error) {
        goto out;
    }

    // Increase counter, start the STUN session & done
    ++candidate->srflx_pending_count;
    // TODO: Maybe add a separate keep-alive interval to the STUN config?
    stun_keepalive_enable(stun_keepalive, candidate->gatherer->config->ice.keepalive_interval);
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        DEBUG_WARNING("Could not create STUN request, reason: %s\n", rawrtc_code_to_str(error));
        mem_deref(session);
    }

    // Un-reference & done
    mem_deref(stun_keepalive);
    return error;
}

/*
 * Gather server reflexive and relay candidates using a specific ICE
 * server.
 */
static void gather_candidates(
        struct rawrtc_candidate_helper* const candidate, // not checked
        struct sa* server_address, // not checked
        struct rawrtc_ice_server_url* const url, // not checked
        struct rawrtc_ice_server* const server // not checked
) {
    enum rawrtc_code error;

    // Skip loopback and link-local candidates
    if (sa_is_loopback(&candidate->candidate->attr.addr)
            || sa_is_linklocal(&candidate->candidate->attr.addr)) {
        return;
    }

    // Gather reflexive candidates
    // NOTE: 'gather_reflexive_candidates' will return 'success' if it cannot gather reflexive
    //       candidates with the provided candidate/server combination.
    // TODO: (BC) REACTIVATE
//    error = gather_reflexive_candidates(candidate, server_address, url);
//    if (error) {
//        DEBUG_WARNING("Could not gather server reflexive candidates, reason: %s\n",
//                      rawrtc_code_to_str(error));
//        // Note: Considered non-critical, continuing
//    }

    // Gather relay candidates
    // Note: 'gather_relay_candidates' will return 'success' if it cannot gather relay
    //       candidates with the provided candidate/server combination.
    // TODO: Once OAuth is implemented, username and password need to be resolved at this point
    error = gather_relay_candidates(candidate, server_address, url, server);
    if (error) {
        DEBUG_WARNING("Could not gather relay candidates, reason: %s\n",
                      rawrtc_code_to_str(error));
        // Note: Considered non-critical, continuing
    }
}

/*
 * Gather server reflexive and relay candidates using a newly resolved
 * ICE server.
 */
static void gather_candidates_using_server(
        struct rawrtc_ice_gatherer* const gatherer,
        struct sa* server_address,
        struct rawrtc_ice_server_url* const url, // not checked
        struct rawrtc_ice_server* const server // not checked
) {
    struct le* le;

    for (le = list_head(&gatherer->local_candidates); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate = le->data;

        // Gather candidates
        gather_candidates(candidate, server_address, url, server);
    }
}

/*
 * Gather server reflexive candidates of a local candidate using
 * an already resolved ICE server.
 */
static void gather_candidates_using_resolved_server(
        struct rawrtc_ice_server* const server, // not checked
        struct rawrtc_candidate_helper* const candidate // not checked
) {
    struct le* le;
    for (le = list_head(&server->urls); le != NULL; le = le->next) {
        struct rawrtc_ice_server_url* const url = le->data;

        // IPv4
        if (candidate->gatherer->config->general.ipv4_enable && !sa_is_any(&url->ipv4_address)) {
            // Gather candidates
            gather_candidates(candidate, &url->ipv4_address, url, server);
        }

        // IPv6
        if (candidate->gatherer->config->general.ipv6_enable && !sa_is_any(&url->ipv6_address)) {
            // Gather candidates
            gather_candidates(candidate, &url->ipv6_address, url, server);
        }
    }
}


/*
 * Gather server reflexive candidates of a local candidate using
 * already resolved ICE servers.
 */
static void gather_candidates_using_resolved_servers(
        struct rawrtc_ice_gatherer* const gatherer, // not checked
        struct rawrtc_candidate_helper* const candidate // not checked
) {
    struct le* le;
    for (le = list_head(&gatherer->options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;

        // Gather on resolved server
        gather_candidates_using_resolved_server(server, candidate);
    }
}

/*
 * Add local candidate, gather server reflexive and relay candidates.
 */
static enum rawrtc_code add_candidate(
        struct rawrtc_ice_gatherer* const gatherer, // not checked
        struct sa const* const address, // not checked
        enum rawrtc_ice_protocol const protocol,
        enum ice_tcptype const tcp_type
) {
    uint32_t priority;
    int const ipproto = rawrtc_ice_protocol_to_ipproto(protocol);
    struct ice_lcand* re_candidate;
    int err;
    struct rawrtc_candidate_helper* candidate;
    enum rawrtc_code error;

    // Add host candidate
    priority = rawrtc_ice_candidate_calculate_priority(
            ICE_CAND_TYPE_HOST, ipproto, sa_af(address), tcp_type);
    // TODO: Set component id properly
    err = trice_lcand_add(
            &re_candidate, gatherer->ice, 1, ipproto, priority, address,
            NULL, ICE_CAND_TYPE_HOST, NULL, tcp_type, NULL, RAWRTC_LAYER_ICE_HOST);
    if (err) {
        DEBUG_WARNING("Could not add host candidate, reason: %m\n", err);
        return rawrtc_error_to_code(err);
    }

    // Create candidate helper (attaches receive handler)
    error = rawrtc_candidate_helper_create(
            &candidate, gatherer, re_candidate, udp_receive_handler, gatherer);
    if (error) {
        DEBUG_WARNING("Could not create candidate helper, reason: %s\n",
                      rawrtc_code_to_str(error));
        return error;
    }

    // Attach trace handler (if trace handle): ICE layer
    // TODO: It could be that we're missing packets here as the socket is being created in
    //       `trice_lcand_add`.
    if (gatherer->trace_handle_ice) {
        error = rawrtc_candidate_helper_attach_packet_trace_handler(
                &candidate->udp_helper_trace_ice, candidate,
                gatherer->trace_handle_ice, RAWRTC_LAYER_TRACE_ICE);
        if (error) {
            DEBUG_NOTICE("Unable to attach ICE packet trace handler, reason: %s\n",
                         rawrtc_code_to_str(error));
        }
    }

    // Add to local candidates list
    list_append(&gatherer->local_candidates, &candidate->le, candidate);
    DEBUG_PRINTF("Added %s host candidate for interface %j\n", rawrtc_ice_protocol_to_str(protocol),
                 address);

    // TODO: Start STUN keep-alive (?)

    // Announce host candidate to handler
    error = announce_candidate(gatherer, re_candidate, NULL);
    if (error) {
        DEBUG_WARNING("Could not announce host candidate, reason: %s\n",
                      rawrtc_code_to_str(error));
        return error;
    }

    // Check state
    // TODO: 'gatherer' might be free'd here
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Gather server reflexive and relay candidates
    gather_candidates_using_resolved_servers(gatherer, candidate);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Local interfaces callback.
 * TODO: Consider ICE gather policy
 * TODO: https://tools.ietf.org/html/draft-ietf-rtcweb-ip-handling-01
  */
static bool interface_handler(
        char const* interface, // not checked
        struct sa const* address, // not checked
        void* arg // not checked
) {
    int af;
    struct rawrtc_ice_gatherer* const gatherer = arg;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    (void) interface;

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return true; // Don't continue gathering
    }

    // TODO: (BC) Remove
    if (list_count(&gatherer->local_candidates) > 0) {
        return true;
    }

    // Skip loopback addresses?
    if (sa_is_loopback(address) && !gatherer->config->general.loopback_enable) {
        return false; // Continue gathering
    }

    // Skip link-local addresses?
    if (sa_is_linklocal(address) && !gatherer->config->general.link_local_enable) {
        return false; // Continue gathering
    }

    // Skip IPv4/IPv6 addresses?
    af = sa_af(address);
    if ((!gatherer->config->general.ipv6_enable && af == AF_INET6)
            || (!gatherer->config->general.ipv4_enable && af == AF_INET)) {
        return false; // Continue gathering
    }

    // TODO: Ignore interfaces gatherered twice

    DEBUG_PRINTF("Gathered local interface %j\n", address);

    // Add UDP candidate
    if (gatherer->config->general.udp_enable) {
        error = add_candidate(gatherer, address, RAWRTC_ICE_PROTOCOL_UDP, ICE_TCP_ACTIVE);
        if (error) {
            DEBUG_WARNING("Could not add candidate, reason: %s", rawrtc_code_to_str(error));
            goto out;
        }

        // Check state
        if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
            return true; // Don't continue gathering
        }
    }

    // Add TCP candidate
    if (gatherer->config->general.tcp_enable) {
        // TODO: Implement TCP support
        //add_candidate(gatherer, address, RAWRTC_ICE_PROTOCOL_TCP, ICE_TCP_SO);
        DEBUG_WARNING("TODO: Add TCP host candidate for interface %j\n", address);
    }

out:
    if (error) {
        // Close and don't continue gathering
        rawrtc_ice_gatherer_close(gatherer);
        return true;
    } else {
        return false; // Continue gathering
    }
}

/*
 * DNS A or AAAA record handler.
 */
static bool dns_record_result_handler(
    struct dnsrr* resource_record,
    void* arg
) {
    struct rawrtc_ice_server_url_dns_context* const context = arg;
    struct rawrtc_ice_server_url* const url = context->url;
    struct rawrtc_ice_server* const server = context->server;
    struct sa* server_address;
    DEBUG_PRINTF("DNS resource record: %H\n", dns_rr_print, resource_record);

    // Set IP address
    switch (resource_record->type) {
        case DNS_TYPE_A:
            // Set IPv4 address
            server_address = &url->ipv4_address;
            sa_set_in(server_address, resource_record->rdata.a.addr, sa_port(server_address));
            break;

        case DNS_TYPE_AAAA:
            // Set IPv6 address
            server_address = &url->ipv6_address;
            sa_set_in6(server_address, resource_record->rdata.aaaa.addr, sa_port(server_address));
            break;

        default:
            DEBUG_WARNING("Invalid DNS resource record, expected A/AAAA record, got: %H\n",
                          dns_rr_print, resource_record);
            return true; // stop traversing
    }

    // Start gathering candidates using the resolved ICE server
    gather_candidates_using_server(context->gatherer, server_address, url, server);

    // Done, stop traversing, one IP is sufficient
    return true;
}

/*
 * DNS query result handler.
 */
static void dns_query_handler(
        int err,
        struct dnshdr const* header,
        struct list* answer_records,
        struct list* authoritive_records,
        struct list* additional_records,
        void* arg
) {
    struct rawrtc_ice_server_url_dns_context* const context = arg;
    (void) header; (void) authoritive_records; (void) additional_records;

    // Handle error (if any)
    if (err) {
        DEBUG_WARNING("Could not query DNS record, reason: %m\n", err);
        goto out;
    }

    // Handle A or AAAA record
    dns_rrlist_apply2(answer_records, NULL, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_CLASS_IN, true,
                      dns_record_result_handler, context);

    // Remove context from URL depending on DNS type
    switch (context->dns_type) {
        case DNS_TYPE_A:
            context->url->dns_a_context = NULL;
            break;

        case DNS_TYPE_AAAA:
            context->url->dns_aaaa_context = NULL;
            break;

        default:
            DEBUG_WARNING("Invalid DNS type, expected A/AAAA, got %s\n",
                          dns_rr_typename((uint16_t) context->dns_type));
            break;
    }

    // Check if gathering is complete
    check_gathering_complete(context->gatherer);

out:
    // Un-reference context
    mem_deref(context);
}

/*
 * Query A or AAAA record.
 */
static enum rawrtc_code query_a_or_aaaa_record(
        struct rawrtc_ice_server_url_dns_context** const contextp, // de-referenced, not checked
        struct sa* const server_address, // not checked
        uint_fast16_t const dns_type,
        struct rawrtc_ice_server_url* const url, // not checked
        struct rawrtc_ice_server* const server, // not checked
        struct rawrtc_ice_gatherer* const gatherer // not checked
) {
    bool const resolved = !sa_is_any(server_address);
    enum rawrtc_code error;
    struct rawrtc_ice_server_url_dns_context* context;
    char* host_str = NULL;

    // Check if already resolved
    if (resolved) {
        DEBUG_PRINTF("Hostname (%s) already resolved: %r -> %j\n",
                     dns_type_to_address_family_name(dns_type), &url->host, server_address);
        return RAWRTC_CODE_SUCCESS;
    }

    // Create ICE server URL DNS context
    error = rawrtc_ice_server_url_dns_context_create(&context, dns_type, url, server, gatherer);
    if (error) {
        return error;
    }

    // Copy URL to str
    error = rawrtc_error_to_code(pl_strdup(&host_str, &url->host));
    if (error) {
        goto out;
    }

    // Query A or AAAA record
    error = rawrtc_error_to_code(dnsc_query(
            &context->dns_query, gatherer->dns_client, host_str, (uint16_t) dns_type,
            DNS_CLASS_IN, true, dns_query_handler, context));
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        // Un-reference context
        mem_deref(context);
    } else {
        // Set pointer
        *contextp = context;
    }

    // Un-reference & done
    mem_deref(host_str);
    return error;
}

/*
 * Cancel if already resolving
 */

/*
 * Resolve ICE server IP addresses.
 */
static enum rawrtc_code resolve_ice_servers_address(
        struct rawrtc_ice_gatherer* const gatherer, // not checked
        struct rawrtc_ice_gather_options* const options // not checked
) {
    struct le* le;

    for (le = list_head(&options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;
        struct le* url_le;
        enum rawrtc_code error;

        for (url_le = list_head(&server->urls); url_le != NULL; url_le = url_le->next) {
            struct rawrtc_ice_server_url* const url = url_le->data;

            // Cancel pending DNS resolve processes
            // TODO: Does this stop the resolving process?
            error = rawrtc_ice_server_url_destroy_dns_contexts(url);
            if (error) {
                DEBUG_WARNING("Could not destroy DNS contexts of ICE server url %s\n", url->url);
                // Continue - not considered critical
            }

            // Query A record (if IPv4 is enabled)
            if (url->need_resolving && gatherer->config->general.ipv4_enable) {
                error = query_a_or_aaaa_record(
                        &url->dns_a_context, &url->ipv4_address, DNS_TYPE_A, url, server, gatherer);
                if (error) {
                    DEBUG_WARNING("Unable to query A record, reason: %s\n",
                                  rawrtc_code_to_str(error));
                    // Continue - not considered critical
                }
            }

            // Query AAAA record (if IPv6 is enabled)
            if (url->need_resolving && gatherer->config->general.ipv6_enable) {
                error = query_a_or_aaaa_record(
                        &url->dns_aaaa_context, &url->ipv6_address, DNS_TYPE_AAAA, url, server,
                        gatherer);
                if (error) {
                    DEBUG_WARNING("Unable to query AAAA record, reason: %s\n",
                                  rawrtc_code_to_str(error));
                    // Continue - not considered critical
                }
            }
        }
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
};

/*
 * Start gathering using an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_gather(
        struct rawrtc_ice_gatherer* const gatherer,
        struct rawrtc_ice_gather_options* options // referenced, nullable
) {
    enum rawrtc_code error;

    // Check arguments
    if (!gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }
    if (!options) {
        options = gatherer->options;
    }

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Already gathering?
    if (gatherer->state == RAWRTC_ICE_GATHERER_GATHERING) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Resolve ICE server IP addresses
    error = resolve_ice_servers_address(gatherer, options);
    if (error) {
        return error;
    }

    // Update state
    set_state(gatherer, RAWRTC_ICE_GATHERER_GATHERING);

    // Start gathering host candidates
    if (options->gather_policy != RAWRTC_ICE_GATHER_POLICY_NOHOST) {
        net_if_apply(interface_handler, gatherer);
    }

    // Gathering complete
    check_gathering_complete(gatherer);

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get local ICE parameters of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_parameters(
        struct rawrtc_ice_parameters** const parametersp, // de-referenced
        struct rawrtc_ice_gatherer* const gatherer
) {
    // Check arguments
    if (!parametersp || !gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Create and return ICE parameters instance
    return rawrtc_ice_parameters_create(
            parametersp, gatherer->ice_username_fragment, gatherer->ice_password, false);
}

/*
 * Destructor for an existing local candidates array.
 */
static void rawrtc_ice_gatherer_local_candidates_destroy(
        void* arg
) {
    struct rawrtc_ice_candidates* const candidates = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < candidates->n_candidates; ++i) {
        mem_deref(candidates->candidates[i]);
    }
}

/*
 * Get local ICE candidates of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_local_candidates(
        struct rawrtc_ice_candidates** const candidatesp, // de-referenced
        struct rawrtc_ice_gatherer* const gatherer
) {
    size_t n;
    struct rawrtc_ice_candidates* candidates;
    struct le* le;
    size_t i;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!candidatesp || !gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get length
    n = list_count(trice_lcandl(gatherer->ice));

    // Allocate & set length immediately
    candidates = mem_zalloc(sizeof(*candidates) + (sizeof(struct rawrtc_ice_candidate*) * n),
                            rawrtc_ice_gatherer_local_candidates_destroy);
    if (!candidates) {
        return RAWRTC_CODE_NO_MEMORY;
    }
    candidates->n_candidates = n;

    // Copy each ICE candidate
    for (le = list_head(trice_lcandl(gatherer->ice)), i = 0; le != NULL; le = le->next, ++i) {
        struct ice_lcand* re_candidate = le->data;

        // Create ICE candidate
        error = rawrtc_ice_candidate_create_from_local_candidate(
                &candidates->candidates[i], re_candidate);
        if (error) {
            goto out;
        }
    }

out:
    if (error) {
        mem_deref(candidates);
    } else {
        // Set pointers
        *candidatesp = candidates;
    }
    return error;
}

/*
 * Add TURN permission for a single remote candidate on all TURN sessions.
 */
enum rawrtc_code rawrtc_ice_gatherer_add_turn_permissions(
        struct rawrtc_ice_gatherer* const gatherer,
        struct ice_rcand* const remote_candidate
) {
    struct le* le_c;
    struct le* le_s;

    // Check arguments
    if (!gatherer || !remote_candidate) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (le_c = list_head(&gatherer->local_candidates); le_c != NULL; le_c = le_c->next) {
        struct rawrtc_candidate_helper* const local_candidate_helper = le_c->data;
        struct list* const sessions = &local_candidate_helper->turn_sessions;
        for (le_s = list_head(sessions); le_s != NULL; le_s = le_s->next) {
            struct rawrtc_candidate_helper_turn_session* const session = le_s->data;

            // Add permission
            // Note: Return code not handled as not considered critical
            add_turn_permission(session, local_candidate_helper->candidate, remote_candidate);
        }
    }
}

/*
 * Print debug information of an ICE gatherer.
 */
int rawrtc_ice_gatherer_debug(
        struct re_printf* const pf,
        struct rawrtc_ice_gatherer const* const gatherer
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!gatherer) {
        return 0;
    }

    // Options
    err |= re_hprintf(pf, "%H", ice_gather_options_debug, gatherer->options);

    err |= re_hprintf(pf, "----- ICE Gatherer <%p> -----\n", gatherer);

    // State
    err |= re_hprintf(pf, "  state=%s\n", rawrtc_ice_gatherer_state_to_name(gatherer->state));

    // Username fragment & password
    err |= re_hprintf(pf, "  username_fragment=\"%s\"\n", gatherer->ice_username_fragment);
    err |= re_hprintf(pf, "  password=\"%s\"\n", gatherer->ice_password);

    // Buffered messages
    err |= re_hprintf(pf, "  buffered_messages=%"PRIu32"\n",
                      list_count(&gatherer->buffered_messages));

    // Candidate helper list
    err |= re_hprintf(pf, "  local_candidates=%"PRIu32"\n",
                      list_count(&gatherer->local_candidates));
    for (le = list_head(&gatherer->local_candidates); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate_helper = le->data;
        err |= re_hprintf(pf, "%H", rawrtc_candidate_helper_debug, candidate_helper);
    }

    // Done
    return err;
}