#include "address.h"
#include "resolver.h"
#include "server.h"
#include <rawrtc/config.h>
#include <rawrtcc/code.h>
#include <rawrtcc/utils.h>
#include <re.h>

#define DEBUG_MODULE "ice-server-url-resolver"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/debug.h>

/*
 * DNS A or AAAA record handler.
 */
static bool dns_record_result_handler(
        struct dnsrr* resource_record,
        void* arg
) {
    struct rawrtc_ice_server_url_resolver* const resolver = arg;
    struct rawrtc_ice_server_url* const url = resolver->url;
    struct sa address;
    enum rawrtc_code error;
    struct rawrtc_ice_server_url_address* url_address;
    bool stop;
    DEBUG_PRINTF("DNS resource record: %H\n", dns_rr_print, resource_record);

    // Set IP address
    sa_cpy(&address, &url->resolved_address);
    switch (resource_record->type) {
        case DNS_TYPE_A:
            // Set IPv4 address
            sa_set_in(&address, resource_record->rdata.a.addr, sa_port(&address));
            break;

        case DNS_TYPE_AAAA:
            // Set IPv6 address
            sa_set_in6(&address, resource_record->rdata.aaaa.addr, sa_port(&address));
            break;

        default:
            DEBUG_WARNING("Invalid DNS resource record, expected A/AAAA record, got: %H\n",
                          dns_rr_print, resource_record);
            return true; // stop traversing
    }

    // Create URL address
    error = rawrtc_ice_server_url_address_create(&url_address, url, &address);
    if (error) {
        DEBUG_WARNING("Unable to create ICE server URL address, reason: %s\n",
                      rawrtc_code_to_str(error));
        return true; // stop traversing
    }

    // Announce resolved IP address
    stop = resolver->address_handler(url_address, resolver->arg);

    // Un-reference
    mem_deref(url_address);

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
        void* arg
) {
    struct rawrtc_ice_server_url_resolver* const resolver = arg;
    (void) header; (void) authoritive_records; (void) additional_records;

    // Handle error (if any)
    if (err) {
        DEBUG_WARNING("Could not query DNS record for '%r', reason: %m\n", &resolver->url->host);
        goto out;
    } else if (header->rcode != 0) {
        DEBUG_NOTICE("DNS record query for '%r' unsuccessful: %s (%"PRIu8")\n",
                     &resolver->url->host, dns_hdr_rcodename(header->rcode), header->rcode);
        goto out;
    }

    // Unlink self from any list
    list_unlink(&resolver->le);

    // Handle A or AAAA record
    dns_rrlist_apply2(answer_records, NULL, DNS_TYPE_A, DNS_TYPE_AAAA, DNS_CLASS_IN, true,
                      dns_record_result_handler, resolver);

out:
    // Unlink & un-reference self
    // Note: We're unlinking twice here since the above unlink may be skipped in an error case.
    //       This is perfectly safe.
    list_unlink(&resolver->le);
    mem_deref(resolver);
}

/*
 * Destructor for an ICE server URL.
 */
static void rawrtc_ice_server_url_resolver_destroy(
        void* arg
) {
    struct rawrtc_ice_server_url_resolver* const resolver = arg;

    // Remove from list
    list_unlink(&resolver->le);

    // Un-reference
    mem_deref(resolver->dns_query);
    mem_deref(resolver->url);
}

/*
 * Create an ICE server URL resolver.
 *
 * Important: Once the handler has been called, the resolver will unlink
 *            from an associated list and un-reference itself.
 */
enum rawrtc_code rawrtc_ice_server_url_resolver_create(
        struct rawrtc_ice_server_url_resolver** const resolverp, // de-referenced
        struct dnsc* const dns_client,
        uint_fast16_t const dns_type,
        struct rawrtc_ice_server_url* const url, // referenced
        rawrtc_ice_server_url_address_resolved_handler address_handler,
        void* const arg
) {
    enum rawrtc_code error;
    struct rawrtc_ice_server_url_resolver* resolver;
    char* host_str;

    // Check arguments
    if (!resolverp || !dns_client || !url || !address_handler) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    resolver = mem_zalloc(sizeof(*resolver), rawrtc_ice_server_url_resolver_destroy);
    if (!resolver) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    resolver->url = mem_ref(url);
    resolver->address_handler = address_handler;
    resolver->arg = arg;
    resolver->dns_type = dns_type;

    // Copy URL to str
    error = rawrtc_error_to_code(pl_strdup(&host_str, &url->host));
    if (error) {
        goto out;
    }

    // Query A or AAAA record
    error = rawrtc_error_to_code(dnsc_query(
            &resolver->dns_query, dns_client, host_str, (uint16_t) dns_type,
            DNS_CLASS_IN, true, dns_query_handler, resolver));
    if (error) {
        goto out;
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference
    mem_deref(host_str);

    if (error) {
        mem_deref(resolver);
    } else {
        // Set pointer & done
        *resolverp = resolver;
    }

    return error;
}
