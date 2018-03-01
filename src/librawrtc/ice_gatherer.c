#include <sys/socket.h> // AF_INET, AF_INET6
#include <netinet/in.h> // IPPROTO_UDP, IPPROTO_TCP
#include <string.h> // memcpy
#include <rawrtcc/internal/message_buffer.h>
#include <rawrtc.h>
#include "config.h"
#include "ice_candidate.h"
#include "candidate_helper.h"
#include "ice_gather_options.h"
#include "ice_gatherer.h"

#define DEBUG_MODULE "ice-gatherer"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#define RAWRTC_DEBUG_ICE_GATHERER 0 // TODO: Remove
#include <rawrtcc/internal/debug.h>

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
}

/*
 * Create a new ICE gatherer.
 * `*gathererp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_gatherer_create(
        struct rawrtc_ice_gatherer** const gathererp, // de-referenced
        struct rawrtc_ice_gather_options* const options, // referenced
        rawrtc_ice_gatherer_state_change_handler* const state_change_handler, // nullable
        rawrtc_ice_gatherer_error_handler* const error_handler, // nullable
        rawrtc_ice_gatherer_local_candidate_handler* const local_candidate_handler, // nullable
        void* const arg // nullable
) {
    struct rawrtc_ice_gatherer* gatherer;
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
    gatherer->state = RAWRTC_ICE_GATHERER_STATE_NEW; // TODO: Raise state (delayed)?
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

    // Set ICE configuration and create trice instance
    // TODO: Add parameters to function arguments?
    gatherer->ice_config.debug = RAWRTC_DEBUG_ICE_GATHERER ? true : false;
    gatherer->ice_config.trace = RAWRTC_DEBUG_ICE_GATHERER ? true : false;
    gatherer->ice_config.ansi = true;
    gatherer->ice_config.enable_prflx = false;
    gatherer->ice_config.nom = ICE_NOMINATION_AGGRESSIVE;
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
    DEBUG_PRINTF("ICE gatherer created:\n%H", rawrtc_ice_gather_options_debug, gatherer->options);

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
    // Check arguments
    if (!gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Already closed?
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return RAWRTC_CODE_SUCCESS;
    }

    // TODO: Stop ICE transport

    // Remove STUN sessions from local candidate helpers
    // Note: Needed to purge remaining references to the gatherer so it can be free'd.
    list_apply(&gatherer->local_candidates, true,
               rawrtc_candidate_helper_remove_stun_sessions_handler, NULL);

    // Flush local candidate helpers
    list_flush(&gatherer->local_candidates);

    // Remove ICE server URL DNS context's
    // TODO: Does this stop the resolving process?
    rawrtc_ice_gather_options_destroy_url_dns_contexts(gatherer->options);

    // Stop ICE checklist (if running)
    trice_checklist_stop(gatherer->ice);

    // Remove ICE agent
    gatherer->ice = mem_deref(gatherer->ice);

    // Set state to closed and return
    set_state(gatherer, RAWRTC_ICE_GATHERER_STATE_CLOSED);
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
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return;
    }

    // Ensure no DNS queries are in flight
    for (le = list_head(&gatherer->options->ice_servers); le != NULL; le = le->next) {
        struct rawrtc_ice_server* const server = le->data;
        struct rawrtc_ice_server_url* url;
        bool pending_dns_queries;

        // Check for pending DNS queries
        error = rawrtc_ice_server_dns_queries_pending(&url, &pending_dns_queries, server);
        if (error) {
            DEBUG_WARNING("Unable to check for pending DNS queries, reason: %s\n",
                          rawrtc_code_to_str(error));
        }

        // Handle pending DNS queries
        if (pending_dns_queries) {
            // Nope
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
    set_state(gatherer, RAWRTC_ICE_GATHERER_STATE_COMPLETE);
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
 * Gather relay candidates on an ICE server.
 */
static enum rawrtc_code gather_relay_candidates(
        struct rawrtc_candidate_helper* const candidate, // not checked
        struct sa* server_address, // not checked
        struct rawrtc_ice_server_url* const url // not checked
) {
    // Check ICE server is enabled for TURN
    if (url->type != RAWRTC_ICE_SERVER_TYPE_TURN) {
        return RAWRTC_CODE_SUCCESS;
    }

    // TODO: Create TURN request
    (void) candidate;
    DEBUG_NOTICE("TODO: Gather relay candidates using server %J (%s)\n", server_address, url->url);
    return RAWRTC_CODE_SUCCESS;
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
    struct ice_lcand* const re_candidate = candidate->candidate;
    struct ice_lcand* re_other_candidate;
    bool remove_session = false;
    uint32_t priority;
    struct ice_lcand* srflx_candidate;
    enum rawrtc_code error;

    // Check state
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return;
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

        // Remove session
        // Note: Removing is delayed here as we still need the references the session has
        //       until the end of the function.
        remove_session = true;
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
            &re_candidate->attr.addr, re_candidate->attr.tcptype, NULL, RAWRTC_LAYER_ICE);
    if (err) {
        DEBUG_WARNING("Could not add server reflexive candidate, reason: %m\n", err);
        goto out;
    }
    DEBUG_PRINTF("Added %s server reflexive candidate for interface %j (%s)\n",
                 net_proto2name(srflx_candidate->attr.proto), address, session->url->url);

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
    struct ice_cand_attr* const attribute = &candidate->candidate->attr;
    enum rawrtc_ice_candidate_type type;
    char const* type_str;
    struct rawrtc_candidate_helper_stun_session* session = NULL;
    struct stun_keepalive* stun_keepalive = NULL;

    // Ensure the candidate's protocol matches the server address's protocol
    if (sa_af(&attribute->addr) != sa_af(server_address)) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Convert ICE candidate type
    error = rawrtc_ice_cand_type_to_ice_candidate_type(&type, attribute->type);
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

    // Create STUN keep-alive session
    // TODO: We're using the candidate's protocol which conflicts with the ICE server URL transport
    DEBUG_PRINTF("Creating STUN request for %s %s candidate %J using ICE server %J (%s)\n",
                 net_proto2name(attribute->proto), type_str, &attribute->addr, server_address,
                 url->url);
    error = rawrtc_error_to_code(stun_keepalive_alloc(
            &stun_keepalive, re_candidate->attr.proto, re_candidate->us, RAWRTC_LAYER_STUN,
            server_address, &rawrtc_default_config.stun_config, reflexive_candidate_handler,
            session));
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
    stun_keepalive_enable(stun_keepalive, rawrtc_default_config.stun_keepalive_interval);
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
        struct rawrtc_ice_server_url* const url // not checked
) {
    enum rawrtc_code error;

    // Gather reflexive candidates
    error = gather_reflexive_candidates(candidate, server_address, url);
    if (error) {
        DEBUG_WARNING("Could not gather server reflexive candidates, reason: %s",
                      rawrtc_code_to_str(error));
        // Note: Considered non-critical, continuing
    }

    // Gather relay candidates
    error = gather_relay_candidates(candidate, server_address, url);
    if (error) {
        DEBUG_WARNING("Could not gather relay candidates, reason: %s",
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
        struct rawrtc_ice_server_url* const url // not checked
) {
    struct le* le;

    for (le = list_head(&gatherer->local_candidates); le != NULL; le = le->next) {
        struct rawrtc_candidate_helper* const candidate = le->data;

        // Gather candidates
        gather_candidates(candidate, server_address, url);
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
        if (rawrtc_default_config.ipv4_enable && !sa_is_any(&url->ipv4_address)) {
            // Gather candidates
            gather_candidates(candidate, &url->ipv4_address, url);
        }

        // IPv6
        if (rawrtc_default_config.ipv6_enable && !sa_is_any(&url->ipv6_address)) {
            // Gather candidates
            gather_candidates(candidate, &url->ipv6_address, url);
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
            NULL, ICE_CAND_TYPE_HOST, NULL, tcp_type, NULL, RAWRTC_LAYER_ICE);
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
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
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
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return true; // Don't continue gathering
    }

    // Ignore loopback and link-local addresses
    // TODO: Make this configurable
    if (sa_is_linklocal(address) || sa_is_loopback(address)) {
        return false; // Continue gathering
    }

    // Skip IPv4, IPv6?
    // TODO: Get config from struct
    af = sa_af(address);
    if ((!rawrtc_default_config.ipv6_enable && af == AF_INET6)
            || (!rawrtc_default_config.ipv4_enable && af == AF_INET)) {
        return false; // Continue gathering
    }

    // TODO: Ignore interfaces gatherered twice

    DEBUG_PRINTF("Gathered local interface %j\n", address);

    // Add UDP candidate
    if (rawrtc_default_config.udp_enable) {
        error = add_candidate(gatherer, address, RAWRTC_ICE_PROTOCOL_UDP, ICE_TCP_ACTIVE);
        if (error) {
            DEBUG_WARNING("Could not add candidate, reason: %s", rawrtc_code_to_str(error));
            goto out;
        }

        // Check state
        if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
            return true; // Don't continue gathering
        }
    }

    // Add TCP candidate
    if (rawrtc_default_config.tcp_enable) {
        // TODO
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
    gather_candidates_using_server(context->gatherer, server_address, url);

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
        struct rawrtc_ice_gatherer* const gatherer // referenced, not checked
) {
    bool const resolved = !sa_is_any(server_address);
    enum rawrtc_code error;
    struct rawrtc_ice_server_url_dns_context* context;
    char* host_str = NULL;

    // Check if already resolved
    if (resolved) {
        DEBUG_PRINTF("Hostname (%s) already resolved\n", dns_type_to_address_family_name(dns_type));
        return RAWRTC_CODE_SUCCESS;
    }

    // Create ICE server URL DNS context
    error = rawrtc_ice_server_url_dns_context_create(&context, dns_type, url, gatherer);
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
        struct rawrtc_ice_server* const ice_server = le->data;
        struct le* url_le;
        enum rawrtc_code error;

        for (url_le = list_head(&ice_server->urls); url_le != NULL; url_le = url_le->next) {
            struct rawrtc_ice_server_url* const url = url_le->data;

            // Cancel pending DNS resolve processes
            // TODO: Does this stop the resolving process?
            error = rawrtc_ice_server_url_destroy_dns_contexts(url);
            if (error) {
                DEBUG_WARNING("Unable to destroy previous DNS context for ICE server URL, reason: "
                              "%s\n", rawrtc_code_to_str(error));
            }

            // Query A record (if IPv4 is enabled)
            if (rawrtc_default_config.ipv4_enable) {
                error = query_a_or_aaaa_record(
                        &url->dns_a_context, &url->ipv4_address, DNS_TYPE_A, url, gatherer);
                if (error) {
                    DEBUG_WARNING("Unable to query A record, reason: %s\n",
                                  rawrtc_code_to_str(error));
                    // Continue - not considered critical
                }
            }

            // Query AAAA record (if IPv6 is enabled)
            if (rawrtc_default_config.ipv6_enable) {
                error = query_a_or_aaaa_record(
                        &url->dns_aaaa_context, &url->ipv6_address, DNS_TYPE_AAAA, url, gatherer);
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
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
        return RAWRTC_CODE_INVALID_STATE;
    }

    // Already gathering?
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_GATHERING) {
        return RAWRTC_CODE_SUCCESS;
    }

    // Resolve ICE server IP addresses
    error = resolve_ice_servers_address(gatherer, options);
    if (error) {
        return error;
    }

    // Update state
    set_state(gatherer, RAWRTC_ICE_GATHERER_STATE_GATHERING);

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
 * Get the current state of an ICE gatherer.
 */
enum rawrtc_code rawrtc_ice_gatherer_get_state(
        enum rawrtc_ice_gatherer_state* const statep, // de-referenced
        struct rawrtc_ice_gatherer* const gatherer
) {
    // Check arguments
    if (!statep || !gatherer) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state
    *statep = gatherer->state;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get local ICE parameters of an ICE gatherer.
 * `*parametersp` must be unreferenced.
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
    if (gatherer->state == RAWRTC_ICE_GATHERER_STATE_CLOSED) {
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
 * `*candidatesp` must be unreferenced.
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
 * Get the corresponding name for an ICE gatherer state.
 */
char const * const rawrtc_ice_gatherer_state_to_name(
        enum rawrtc_ice_gatherer_state const state
) {
    switch (state) {
        case RAWRTC_ICE_GATHERER_STATE_NEW:
            return "new";
        case RAWRTC_ICE_GATHERER_STATE_GATHERING:
            return "gathering";
        case RAWRTC_ICE_GATHERER_STATE_COMPLETE:
            return "complete";
        case RAWRTC_ICE_GATHERER_STATE_CLOSED:
            return "closed";
        default:
            return "???";
    }
}
