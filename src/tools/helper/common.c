#include <string.h> // strerror
#include <rawrtc.h>
#include "common.h"

#define DEBUG_MODULE "helper-common"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Ignore success code list.
 */
enum rawrtc_code const ignore_success[] = {RAWRTC_CODE_SUCCESS};
size_t const ignore_success_length = ARRAY_SIZE(ignore_success);

/*
 * Function to be called before exiting.
 */
void before_exit() {
    // Close
    rawrtc_close();

    // Check memory leaks
    tmr_debug();
    mem_debug();
}

/*
 * Exit on error code.
 */
void exit_on_error(
        enum rawrtc_code const code,
        enum rawrtc_code const ignore[],
        size_t const n_ignore,
        char const* const file,
        uint32_t const line
) {
    size_t i;

    // Ignore?
    for (i = 0; i < n_ignore; ++i) {
        if (code == ignore[i]) {
            return;
        }
    }

    // Handle
    switch (code) {
        case RAWRTC_CODE_SUCCESS:
            return;
        case RAWRTC_CODE_NOT_IMPLEMENTED:
            DEBUG_WARNING("Not implemented in %s %"PRIu32"\n",
                          file, line);
            return;
        default:
            DEBUG_WARNING("Error in %s %"PRIu32" (%d): %s\n",
                          file, line, code, rawrtc_code_to_str(code));
            before_exit();
            exit((int) code);
    }
}

/*
 * Exit on POSIX error code.
 */
void exit_on_posix_error(
        int code,
        char const* const file,
        uint32_t line
) {
    if (code != 0) {
        DEBUG_WARNING("Error in %s %"PRIu32" (%d): %s\n", file, line, code, strerror(code));
        before_exit();
        exit(code);
    }
}

/*
 * Exit with a custom error message.
 */
void exit_with_error(
        char const* const file,
        uint32_t line,
        char const* const formatter,
        ...
) {
    char* message;

    // Format message
    va_list ap;
    va_start(ap, formatter);
    re_vsdprintf(&message, formatter, ap);
    va_end(ap);

    // Print message
    DEBUG_WARNING("%s %"PRIu32": %s\n", file, line, message);

    // Un-reference & bye
    mem_deref(message);
    before_exit();
    exit(1);
}

/*
 * Check if the ICE candidate type is enabled.
 */
bool ice_candidate_type_enabled(
        struct client* const client,
        enum rawrtc_ice_candidate_type const type
) {
    char const* const type_str = rawrtc_ice_candidate_type_to_str(type);
    size_t i;

    // All enabled?
    if (client->n_ice_candidate_types == 0) {
        return true;
    }

    // Specifically enabled?
    for (i = 0; i < client->n_ice_candidate_types; ++i) {
        if (str_cmp(client->ice_candidate_types[i], type_str) == 0) {
            return true;
        }
    }

    // Nope
    return false;
}

/*
 * Print ICE candidate information.
 */
void print_ice_candidate(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        struct client* const client
) {
    if (candidate) {
        enum rawrtc_code const ignore[] = {RAWRTC_CODE_NO_VALUE};
        enum rawrtc_code error;
        char* foundation;
        enum rawrtc_ice_protocol protocol;
        uint32_t priority;
        char* ip;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type;
        char const* tcp_type_str = "N/A";
        char* related_address = NULL;
        uint16_t related_port = 0;
        bool is_enabled;

        // Get candidate information
        EOE(rawrtc_ice_candidate_get_foundation(&foundation, candidate));
        EOE(rawrtc_ice_candidate_get_protocol(&protocol, candidate));
        EOE(rawrtc_ice_candidate_get_priority(&priority, candidate));
        EOE(rawrtc_ice_candidate_get_ip(&ip, candidate));
        EOE(rawrtc_ice_candidate_get_port(&port, candidate));
        EOE(rawrtc_ice_candidate_get_type(&type, candidate));
        error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        switch (error) {
            case RAWRTC_CODE_SUCCESS:
                tcp_type_str = rawrtc_ice_tcp_candidate_type_to_str(tcp_type);
                break;
            case RAWRTC_CODE_NO_VALUE:
                break;
            default:
                EOE(error);
                break;
        }
        EOEIGN(rawrtc_ice_candidate_get_related_address(&related_address, candidate), ignore);
        EOEIGN(rawrtc_ice_candidate_get_related_port(&related_port, candidate), ignore);
        is_enabled = ice_candidate_type_enabled(client, type);

        // Print candidate
        dbg_printf(
                is_enabled ? DBG_INFO : DBG_DEBUG,
                "(%s) ICE gatherer local candidate: foundation=%s, protocol=%s, priority=%"PRIu32""
                        ", ip=%s, port=%"PRIu16", type=%s, tcp-type=%s, related-address=%s,"
                        "related-port=%"PRIu16"; URL: %s; %s\n",
                client->name, foundation, rawrtc_ice_protocol_to_str(protocol), priority, ip, port,
                rawrtc_ice_candidate_type_to_str(type), tcp_type_str,
                related_address ? related_address : "N/A", related_port, url ? url : "N/A",
                is_enabled ? "enabled" : "disabled");

        // Unreference
        mem_deref(related_address);
        mem_deref(ip);
        mem_deref(foundation);
    } else {
        DEBUG_INFO("(%s) ICE gatherer last local candidate\n", client->name);
    }
}
