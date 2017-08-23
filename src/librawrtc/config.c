#include <string.h> // memcpy
#include <rawrtc.h>
#include "config.h"

/*
 * Default configuration's dummy local address.
 */
char const rawrtc_config_default_dummy_local_address[] = "10.0.0.1:1000";
size_t const rawrtc_config_default_dummy_local_address_length =
        ARRAY_SIZE(rawrtc_config_default_dummy_local_address);

/*
 * Default configuration's dummy remote address.
 */
char const rawrtc_config_default_dummy_remote_address[] = "10.0.0.2:2000";
size_t const rawrtc_config_default_dummy_remote_address_length =
        ARRAY_SIZE(rawrtc_config_default_dummy_remote_address);

/*
 * Default configuration.
 */
struct rawrtc_config rawrtc_default_config = {
    .debug = {
        // Debug log level
        .log_level = RAWRTC_LOG_LEVEL_ALL_TEMP,
        // Enable ANSI colours for logging
        .log_colors_enable = true,
        // Dump packets from layers into that directory. Supply `NULL` to disable.
        // Note: This can slow down the event loop.
        .packet_trace_path = "/tmp/rawrtc" // TODO: (BC) NULL
    },
    .general = {
        // Enable IPv4
        .ipv4_enable = true,
        // Enable IPv6
        .ipv6_enable = false, // TODO: (BC) true
        // Enable UDP transport
        .udp_enable = true,
        // Enable TCP transport
        .tcp_enable = false, // TODO: true by default
        // Enable loopback addresses
        .loopback_enable = false, // TODO: (BC) true
        // Enable link-local addresses
        .link_local_enable = false,
        // Sign algorithm used for created certificates
        .sign_algorithm = RAWRTC_CERTIFICATE_SIGN_ALGORITHM_SHA256
    },
    .ice = {
        // Enable peer reflexive candidates
        .prflx_enable = false, // TODO: true by default
        // Remote candidate keep-alive interval (s)
        .keepalive_interval = 25,
        // Candidate pair checklist pacing interval (ms)
        .checklist_pacing_interval = 20,
    },
    .ice_server = {
        // Default transport if no `?transport` has been provided for `stun:` or `turn:` server
        .default_normal_transport = RAWRTC_ICE_SERVER_TRANSPORT_UDP,
        // Default transport if no `?transport` has been provided for `stuns:` or `turns:` server
        .default_secure_transport = RAWRTC_ICE_SERVER_TRANSPORT_TLS,
    },
    .stun = {
        // Retransmission timeout (ms)
        .retransmission_timeout = STUN_DEFAULT_RTO,
        // Retransmission count
        .retransmission_count = STUN_DEFAULT_RC,
        // Maximum retransmissions
        .retransmissions_max = STUN_DEFAULT_RM,
        // Timeout for reliable transport (ms)
        .reliable_transport_timeout = STUN_DEFAULT_TI,
        // Type of service (TOS) field
        .tos = 0x00
    },
    .turn = {
        // TURN allocation lifetime (s)
        .allocation_lifetime = 600
    }
};

/*
 * Create a RAWRTC configuration.
 *
 * Will start with the default configuration. Each configuration group has its own
 * setter function.
 */
enum rawrtc_code rawrtc_config_create(
        struct rawrtc_config** const configp // de-referenced
) {
    struct rawrtc_config* config;

    // Check arguments
    if (!configp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    // Note: Non-zero memory allocation due to copy afterwards
    config = mem_alloc(sizeof(*config), NULL);
    if (!config) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Copy default configuration
    memcpy(config, &rawrtc_default_config, sizeof(config));

    // Set pointer & done
    *configp = config;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get debug configuration options.
 */
enum rawrtc_code rawrtc_config_get_debug_options(
        struct rawrtc_config* const config,
        char** const packet_trace_pathp, // de-referenced, nullable
        struct sa* const dummy_local_addressp, // de-referenced, nullable
        struct sa* const dummy_remote_addressp // de-referenced, nullable
) {
    enum rawrtc_code error;

    // Check arguments
    if (!config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy packet dump path (if requested and if any)
    if (packet_trace_pathp && config->debug.packet_trace_path) {
        error = rawrtc_strdup(packet_trace_pathp, config->debug.packet_trace_path);
        if (error) {
            return error;
        }
    }

    // Copy addresses (if requested)
    if (dummy_local_addressp) {
        *dummy_local_addressp = config->debug.dummy_local_address;
    }
    if (dummy_remote_addressp) {
        *dummy_remote_addressp = config->debug.dummy_remote_address;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set debug configuration options.
 */
enum rawrtc_code rawrtc_config_set_debug_options(
        struct rawrtc_config* const config,
        char* const packet_trace_path, // nullable, copied
        struct sa* const dummy_local_address, // nullable, copied
        struct sa* const dummy_remote_address // nullable, copied
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy packet dump path (if any)
    if (packet_trace_path) {
        enum rawrtc_code const error = rawrtc_strdup(
                &config->debug.packet_trace_path, packet_trace_path);
        if (error) {
            return error;
        }
    }

    // Copy addresses (if any)
    if (dummy_local_address) {
        config->debug.dummy_local_address = *dummy_local_address;
    }
    if (dummy_remote_address) {
        config->debug.dummy_remote_address = *dummy_remote_address;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get general configuration options.
 */
enum rawrtc_code rawrtc_config_get_general_options(
        struct rawrtc_config* const config,
        bool* const ipv4_enablep, // de-referenced, nullable
        bool* const ipv6_enablep, // de-referenced, nullable
        bool* const udp_enablep, // de-referenced, nullable
        bool* const tcp_enablep // de-referenced, nullable
) {
    // Check arguments
    if (!config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy values
    if (ipv4_enablep) {
        *ipv4_enablep = config->general.ipv4_enable;
    }
    if (ipv6_enablep) {
        *ipv6_enablep = config->general.ipv6_enable;
    }
    if (udp_enablep) {
        *udp_enablep = config->general.udp_enable;
    }
    if (tcp_enablep) {
        *tcp_enablep = config->general.tcp_enable;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set general configuration options.
 */
enum rawrtc_code rawrtc_config_set_general_options(
        struct rawrtc_config* const config,
        bool const ipv4_enable,
        bool const ipv6_enable,
        bool const udp_enable,
        bool const tcp_enable
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields
    config->general.ipv4_enable = ipv4_enable;
    config->general.ipv6_enable = ipv6_enable;
    config->general.udp_enable = udp_enable;
    config->general.tcp_enable = tcp_enable;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get ICE configuration options.
 */
enum rawrtc_code rawrtc_config_get_ice_options(
        struct rawrtc_config* const config,
        uint32_t* const keepalive_intervalp, // de-referenced, nullable
        uint32_t* const checklist_packing_intervalp // de-referenced, nullable
) {
    // Check arguments
    if (!config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy values
    if (keepalive_intervalp) {
        *keepalive_intervalp = config->ice.keepalive_interval;
    }
    if (checklist_packing_intervalp) {
        *checklist_packing_intervalp = config->ice.checklist_pacing_interval;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set ICE configuration options.
 */
enum rawrtc_code rawrtc_config_set_ice_options(
        struct rawrtc_config* const config,
        uint32_t const keepalive_interval,
        uint32_t const checklist_packing_interval
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields
    config->ice.keepalive_interval = keepalive_interval;
    config->ice.checklist_pacing_interval = checklist_packing_interval;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get ICE server configuration options.
 */
enum rawrtc_code rawrtc_config_get_ice_server_options(
        struct rawrtc_config* const config,
        enum rawrtc_ice_server_transport* const default_normal_transportp, // de-referenced, nullable
        enum rawrtc_ice_server_transport* const default_secure_transportp // de-referenced, nullable
) {
    // Check arguments
    if (!config || !default_normal_transportp || !default_secure_transportp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy values
    if (default_normal_transportp) {
        *default_normal_transportp = config->ice_server.default_normal_transport;
    }
    if (default_secure_transportp) {
        *default_secure_transportp = config->ice_server.default_secure_transport;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set ICE server configuration options.
 */
enum rawrtc_code rawrtc_config_set_ice_server_options(
        struct rawrtc_config* const config,
        enum rawrtc_ice_server_transport const default_normal_transport,
        enum rawrtc_ice_server_transport const default_secure_transport
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields
    config->ice_server.default_normal_transport = default_normal_transport;
    config->ice_server.default_secure_transport = default_secure_transport;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get STUN configuration options.
 */
enum rawrtc_code rawrtc_config_get_stun_options(
        struct rawrtc_config* const config,
        uint32_t* const retransmission_timeoutp, // de-referenced, nullable
        uint32_t* const retransmission_countp, // de-referenced, nullable
        uint32_t* const retransmissions_maxp, // de-referenced, nullable
        uint32_t* const reliable_transport_timeoutp, // de-referenced, nullable
        uint8_t* const tosp // de-referenced, nullable
) {
    // Check arguments
    if (!config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy values
    if (retransmission_timeoutp) {
        *retransmission_timeoutp = config->stun.retransmission_timeout;
    }
    if (retransmission_countp) {
        *retransmission_countp = config->stun.retransmission_count;
    }
    if (retransmissions_maxp) {
        *retransmissions_maxp = config->stun.retransmissions_max;
    }
    if (reliable_transport_timeoutp) {
        *reliable_transport_timeoutp = config->stun.reliable_transport_timeout;
    }
    if (tosp) {
        *tosp = config->stun.tos;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set STUN configuration options.
 */
enum rawrtc_code rawrtc_config_set_stun_options(
        struct rawrtc_config* const config,
        uint32_t const retransmission_timeout,
        uint32_t const retransmission_count,
        uint32_t const retransmissions_max,
        uint32_t const reliable_transport_timeout,
        uint8_t const tos
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields
    config->stun.retransmission_timeout = retransmission_timeout;
    config->stun.retransmission_count = retransmission_count;
    config->stun.retransmissions_max = retransmissions_max;
    config->stun.reliable_transport_timeout = reliable_transport_timeout;
    config->stun.tos = tos;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get TURN configuration options.
 */
enum rawrtc_code rawrtc_config_get_turn_options(
        struct rawrtc_config* const config,
        uint32_t* const allocation_lifetimep // de-referenced, nullable
) {
    // Check arguments
    if (!config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy values
    if (allocation_lifetimep) {
        *allocation_lifetimep = config->turn.allocation_lifetime;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Set TURN configuration options.
 */
enum rawrtc_code rawrtc_config_set_turn_options(
        struct rawrtc_config* const config,
        uint32_t const allocation_lifetime
) {
    // Check arguments
    if (!config || config == &rawrtc_default_config) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set fields
    config->turn.allocation_lifetime = allocation_lifetime;

    // Done
    return RAWRTC_CODE_SUCCESS;
}
