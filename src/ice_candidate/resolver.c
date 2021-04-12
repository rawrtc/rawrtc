#include "resolver.h"
#include <rawrtc/config.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

#define DEBUG_MODULE "ice-candidate-mdns-resolver"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * DNS A or AAAA record handler.
 */
static bool dns_record_result_handler(struct dnsrr* resource_record, void* arg) {
    struct rawrtc_ice_candidate_mdns_resolver* const resolver = arg;
    struct sa address;
    bool stop;
    DEBUG_PRINTF("DNS resource record: %H\n", dns_rr_print, resource_record);

    // Set IP address
    switch (resource_record->type) {
        case DNS_TYPE_A:
            // Set IPv4 address
            sa_set_in(&address, resource_record->rdata.a.addr, 0);
            break;

        case DNS_TYPE_AAAA:
            // Set IPv6 address
            sa_set_in6(&address, resource_record->rdata.aaaa.addr, 0);
            break;

        default:
            DEBUG_WARNING(
                "Invalid DNS resource record, expected A/AAAA record, got: %H\n", dns_rr_print,
                resource_record);
            return true;  // stop traversing
    }

    // Announce resolved IP address
    stop =
        resolver->address_handler(resolver->candidate, resolver->hostname, &address, resolver->arg);

    // Done (continue or stop traversing)
    return stop;
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
    void* arg) {
    struct rawrtc_ice_candidate_mdns_resolver* const resolver = arg;
    (void) header;
    (void) authoritive_records;
    (void) additional_records;

    // Handle error (if any)
    if (err) {
        DEBUG_WARNING("Could not query DNS record for '%s', reason: %m\n", resolver->hostname, err);
        goto out;
    } else if (header->rcode != 0) {
        DEBUG_NOTICE(
            "DNS record query for '%s' unsuccessful: %s (%" PRIu8 ")\n", resolver->hostname,
            dns_hdr_rcodename(header->rcode), header->rcode);
        goto out;
    }

    // Unlink self from any list
    list_unlink(&resolver->le);

    // Handle A or AAAA record
    dns_rrlist_apply2(
        answer_records, NULL, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_CLASS_IN, true,
        dns_record_result_handler, resolver);

out:
    // Unlink & un-reference self
    // Note: We're unlinking twice here since the above unlink may be skipped in an error case.
    //       This is perfectly safe.
    list_unlink(&resolver->le);
    mem_deref(resolver);
}

/*
 * Destructor for an ICE candidate mDNS hostname resolver.
 */
static void rawrtc_ice_candidate_mdns_resolver_destroy(void* arg) {
    struct rawrtc_ice_candidate_mdns_resolver* const resolver = arg;

    // Remove from list
    list_unlink(&resolver->le);

    // Un-reference
    mem_deref(resolver->dns_query);
    mem_deref(resolver->hostname);
    mem_deref(resolver->candidate);
}

/*
 * Create an ICE candidate mDNS hostname resolver.
 *
 * Important: Once the handler has been called, the resolver will unlink
 *            from an associated list and un-reference itself.
 */
enum rawrtc_code rawrtc_ice_candidate_mdns_resolver_create(
    struct rawrtc_ice_candidate_mdns_resolver** const resolverp,  // de-referenced
    struct dnsc* const dns_client,
    uint_fast16_t const dns_type,
    struct rawrtc_ice_candidate* const candidate,  // referenced
    char* const hostname,
    rawrtc_ice_candidate_mdns_address_resolved_handler address_handler,
    void* const arg) {
    enum rawrtc_code error;
    struct rawrtc_ice_candidate_mdns_resolver* resolver;

    // Check arguments
    if (!resolverp || !dns_client || !candidate || !address_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    resolver = mem_zalloc(sizeof(*resolver), rawrtc_ice_candidate_mdns_resolver_destroy);
    if (!resolver) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    resolver->candidate = mem_ref(candidate);
    resolver->address_handler = address_handler;
    resolver->arg = arg;
    resolver->dns_type = dns_type;

    // Copy hostname
    error = rawrtc_strdup(&resolver->hostname, hostname);
    if (error) {
        goto out;
    }

    // Query A or AAAA record
    error = rawrtc_error_to_code(dnsc_query(
        &resolver->dns_query, dns_client, hostname, (uint16_t) dns_type, DNS_CLASS_IN, true,
        dns_query_handler, resolver));
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    if (error) {
        mem_deref(resolver);
    } else {
        // Set pointer & done
        *resolverp = resolver;
    }

    return error;
}
