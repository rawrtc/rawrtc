#include <stdio.h>
#include <rawrtc.h>
#include "common.h"
#include "utils.h"
#include "parameters.h"

#define DEBUG_MODULE "helper-parameters"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Set ICE parameters in dictionary.
 */
void set_ice_parameters(
        struct rawrtc_ice_parameters* const parameters,
        struct odict* const dict
) {
    char* username_fragment;
    char* password;
    bool ice_lite;

    // Get values
    EOE(rawrtc_ice_parameters_get_username_fragment(&username_fragment, parameters));
    EOE(rawrtc_ice_parameters_get_password(&password, parameters));
    EOE(rawrtc_ice_parameters_get_ice_lite(&ice_lite, parameters));

    // Set ICE parameters
    EOR(odict_entry_add(dict, "usernameFragment", ODICT_STRING, username_fragment));
    EOR(odict_entry_add(dict, "password", ODICT_STRING, password));
    EOR(odict_entry_add(dict, "iceLite", ODICT_BOOL, ice_lite));

    // Un-reference values
    mem_deref(password);
    mem_deref(username_fragment);
}

/*
 * Set ICE candidates in dictionary.
 */
void set_ice_candidates(
        struct rawrtc_ice_candidates* const parameters,
        struct odict* const array
) {
    size_t i;
    struct odict* node;

    // Set ICE candidates
    for (i = 0; i < parameters->n_candidates; ++i) {
        enum rawrtc_code error;
        struct rawrtc_ice_candidate* const candidate = parameters->candidates[i];
        char* foundation;
        uint32_t priority;
        char* ip;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        enum rawrtc_ice_candidate_type type;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;
        char* key;

        // Create object
        EOR(odict_alloc(&node, 16));

        // Get values
        EOE(rawrtc_ice_candidate_get_foundation(&foundation, candidate));
        EOE(rawrtc_ice_candidate_get_priority(&priority, candidate));
        EOE(rawrtc_ice_candidate_get_ip(&ip, candidate));
        EOE(rawrtc_ice_candidate_get_protocol(&protocol, candidate));
        EOE(rawrtc_ice_candidate_get_port(&port, candidate));
        EOE(rawrtc_ice_candidate_get_type(&type, candidate));
        error = rawrtc_ice_candidate_get_tcp_type(&tcp_type, candidate);
        EOE(error == RAWRTC_CODE_NO_VALUE ? RAWRTC_CODE_SUCCESS : error);
        error = rawrtc_ice_candidate_get_related_address(&related_address, candidate);
        EOE(error == RAWRTC_CODE_NO_VALUE ? RAWRTC_CODE_SUCCESS : error);
        error = rawrtc_ice_candidate_get_related_port(&related_port, candidate);
        EOE(error == RAWRTC_CODE_NO_VALUE ? RAWRTC_CODE_SUCCESS : error);

        // Set ICE candidate values
        EOR(odict_entry_add(node, "foundation", ODICT_STRING, foundation));
        EOR(odict_entry_add(node, "priority", ODICT_INT, (int64_t) priority));
        EOR(odict_entry_add(node, "ip", ODICT_STRING, ip));
        EOR(odict_entry_add(node, "protocol", ODICT_STRING, rawrtc_ice_protocol_to_str(protocol)));
        EOR(odict_entry_add(node, "port", ODICT_INT, (int64_t) port));
        EOR(odict_entry_add(node, "type", ODICT_STRING, rawrtc_ice_candidate_type_to_str(type)));
        if (protocol == RAWRTC_ICE_PROTOCOL_TCP) {
            EOR(odict_entry_add(node, "tcpType", ODICT_STRING,
                                rawrtc_ice_tcp_candidate_type_to_str(tcp_type)));
        }
        if (related_address) {
            EOR(odict_entry_add(node, "relatedAddress", ODICT_STRING, related_address));
        }
        if (related_port > 0) {
            EOR(odict_entry_add(node, "relatedPort", (int64_t) ODICT_INT, related_port));
        }

        // Add to array
        EOE(rawrtc_sdprintf(&key, "%zu", i));
        EOR(odict_entry_add(array, key, ODICT_OBJECT, node));

        // Un-reference values
        mem_deref(key);
        mem_deref(related_address);
        mem_deref(ip);
        mem_deref(foundation);
        mem_deref(node);
    }
}

/*
 * Set DTLS parameters in dictionary.
 */
void set_dtls_parameters(
        struct rawrtc_dtls_parameters* const parameters,
        struct odict* const dict
) {
    enum rawrtc_dtls_role role;
    struct odict* array;
    struct odict* node;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;

    // Get and set DTLS role
    EOE(rawrtc_dtls_parameters_get_role(&role, parameters));
    EOR(odict_entry_add(dict, "role", ODICT_STRING, rawrtc_dtls_role_to_str(role)));

    // Create array
    EOR(odict_alloc(&array, 16));

    // Get and set fingerprints
    EOE(rawrtc_dtls_parameters_get_fingerprints(&fingerprints, parameters));
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint = fingerprints->fingerprints[i];
        enum rawrtc_certificate_sign_algorithm sign_algorithm;
        char* value;
        char* key;

        // Create object
        EOR(odict_alloc(&node, 16));

        // Get values
        EOE(rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(&sign_algorithm, fingerprint));
        EOE(rawrtc_dtls_parameters_fingerprint_get_value(&value, fingerprint));

        // Set fingerprint values
        EOR(odict_entry_add(node, "algorithm", ODICT_STRING,
                            rawrtc_certificate_sign_algorithm_to_str(sign_algorithm)));
        EOR(odict_entry_add(node, "value", ODICT_STRING, value));

        // Add to array
        EOE(rawrtc_sdprintf(&key, "%zu", i));
        EOR(odict_entry_add(array, key, ODICT_OBJECT, node));

        // Un-reference values
        mem_deref(key);
        mem_deref(value);
        mem_deref(node);
    }

    // Un-reference fingerprints
    mem_deref(fingerprints);

    // Add array to object
    EOR(odict_entry_add(dict, "fingerprints", ODICT_ARRAY, array));
    mem_deref(array);
}

/*
 * Set SCTP parameters in dictionary.
 */
void set_sctp_parameters(
        struct rawrtc_sctp_transport* const transport,
        struct sctp_parameters* const parameters,
        struct odict* const dict
) {
    uint64_t max_message_size;
    uint16_t port;

    // Get values
    EOE(rawrtc_sctp_capabilities_get_max_message_size(&max_message_size, parameters->capabilities));
    EOE(rawrtc_sctp_transport_get_port(&port, transport));

    // Ensure maximum message size fits into int64
    if (max_message_size > INT64_MAX) {
        EOE(RAWRTC_CODE_INSUFFICIENT_SPACE);
    }

    // Set ICE parameters
    EOR(odict_entry_add(dict, "maxMessageSize", ODICT_INT, (int64_t) max_message_size));
    EOR(odict_entry_add(dict, "port", ODICT_INT, (int64_t) port));
}

#ifdef SCTP_REDIRECT_TRANSPORT
/*
 * Set SCTP redirect parameters in dictionary.
 */
void set_sctp_redirect_parameters(
        struct rawrtc_sctp_redirect_transport* const transport,
        struct sctp_parameters* const parameters,
        struct odict* const dict
) {
    uint64_t max_message_size;
    uint16_t port;

    // Get values
    EOE(rawrtc_sctp_capabilities_get_max_message_size(&max_message_size, parameters->capabilities));
    EOE(rawrtc_sctp_redirect_transport_get_port(&port, transport));

    // Ensure maximum message size fits into int64
    if (max_message_size > INT64_MAX) {
        EOE(RAWRTC_CODE_INSUFFICIENT_SPACE);
    }

    // Set ICE parameters
    EOR(odict_entry_add(dict, "maxMessageSize", ODICT_INT, (int64_t) max_message_size));
    EOR(odict_entry_add(dict, "port", ODICT_INT, (int64_t) port));
}
#endif

/*
 * Get ICE parameters from dictionary.
 */
enum rawrtc_code get_ice_parameters(
        struct rawrtc_ice_parameters** const parametersp,
        struct odict* const dict
) {
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    char* username_fragment;
    char* password;
    bool ice_lite;

    // Get ICE parameters
    error |= dict_get_entry(&username_fragment, dict, "usernameFragment", ODICT_STRING, true);
    error |= dict_get_entry(&password, dict, "password", ODICT_STRING, true);
    error |= dict_get_entry(&ice_lite, dict, "iceLite", ODICT_BOOL, true);
    if (error) {
        return error;
    }

    // Create ICE parameters instance
    return rawrtc_ice_parameters_create(parametersp, username_fragment, password, ice_lite);
}

static void ice_candidates_destroy(
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
 * Get ICE candidates from dictionary.
 * Filter by enabled ICE candidate types if `client` argument is set to
 * non-NULL.
 */
enum rawrtc_code get_ice_candidates(
        struct rawrtc_ice_candidates** const candidatesp,
        struct odict* const dict,
        struct client* const client
) {
    size_t n;
    struct rawrtc_ice_candidates* candidates;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct le* le;

    // Get length
    n = list_count(&dict->lst);

    // Allocate & set length immediately
    // Note: We allocate more than we need in case ICE candidate types are being filtered but... meh
    candidates = mem_zalloc(sizeof(*candidates) + (sizeof(struct rawrtc_ice_candidate*) * n),
                            ice_candidates_destroy);
    if (!candidates) {
        EWE("No memory to allocate ICE candidates array");
    }
    candidates->n_candidates = 0;

    // Get ICE candidates
    for (le = list_head(&dict->lst); le != NULL; le = le->next) {
        struct odict* const node = ((struct odict_entry*) le->data)->u.odict;
        char const* type_str = NULL;
        enum rawrtc_ice_candidate_type type;
        char* foundation;
        uint32_t priority;
        char* ip;
        char const* protocol_str = NULL;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        char const* tcp_type_str = NULL;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;
        struct rawrtc_ice_candidate* candidate;

        // Get ICE candidate
        error |= dict_get_entry(&type_str, node, "type", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_candidate_type(&type, type_str);
        error |= dict_get_entry(&foundation, node, "foundation", ODICT_STRING, true);
        error |= dict_get_uint32(&priority, node, "priority", true);
        error |= dict_get_entry(&ip, node, "ip", ODICT_STRING, true);
        error |= dict_get_entry(&protocol_str, node, "protocol", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_protocol(&protocol, protocol_str);
        error |= dict_get_uint16(&port, node, "port", true);
        if (protocol == RAWRTC_ICE_PROTOCOL_TCP) {
            error |= dict_get_entry(&tcp_type_str, node, "tcpType", ODICT_STRING, true);
            error |= rawrtc_str_to_ice_tcp_candidate_type(&tcp_type, tcp_type_str);
        }
        dict_get_entry(&related_address, node, "relatedAddress", ODICT_STRING, false);
        dict_get_uint16(&related_port, node, "relatedPort", false);
        if (error) {
            goto out;
        }

        // Create and add ICE candidate
        error = rawrtc_ice_candidate_create(
                &candidate, foundation, priority, ip, protocol, port, type,
                tcp_type, related_address, related_port);
        if (error) {
            goto out;
        }

        // Print ICE candidate
        print_ice_candidate(candidate, NULL, NULL, client);

        // Store if ICE candidate type enabled
        if (ice_candidate_type_enabled(client, type)) {
            candidates->candidates[candidates->n_candidates++] = candidate;
        } else {
            mem_deref(candidate);
        }
    }

out:
    if (error) {
        mem_deref(candidates);
    } else {
        // Set pointer
        *candidatesp = candidates;
    }
    return error;
}

static void dtls_fingerprints_destroy(
        void* arg
) {
    struct rawrtc_dtls_fingerprints* const fingerprints = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        mem_deref(fingerprints->fingerprints[i]);
    }
}

/*
 * Get DTLS parameters from dictionary.
 */
enum rawrtc_code get_dtls_parameters(
        struct rawrtc_dtls_parameters** const parametersp,
        struct odict* const dict
) {
    size_t n;
    struct rawrtc_dtls_parameters* parameters = NULL;
    struct rawrtc_dtls_fingerprints* fingerprints;
    enum rawrtc_code error;
    char const* role_str = NULL;
    enum rawrtc_dtls_role role;
    struct odict* node;
    struct le* le;
    size_t i;

    // Get fingerprints array and length
    error = dict_get_entry(&node, dict, "fingerprints", ODICT_ARRAY, true);
    if (error) {
        return error;
    }
    n = list_count(&node->lst);

    // Allocate & set length immediately
    fingerprints = mem_zalloc(
            sizeof(*fingerprints) + (sizeof(struct rawrtc_dtls_fingerprints*) * n),
            dtls_fingerprints_destroy);
    if (!fingerprints) {
        EWE("No memory to allocate DTLS fingerprint array");
    }
    fingerprints->n_fingerprints = n;

    // Get role
    error |= dict_get_entry(&role_str, dict, "role", ODICT_STRING, true);
    error |= rawrtc_str_to_dtls_role(&role, role_str);
    if (error) {
        role = RAWRTC_DTLS_ROLE_AUTO;
    }

    // Get fingerprints
    for (le = list_head(&node->lst), i = 0; le != NULL; le = le->next, ++i) {
        node = ((struct odict_entry*) le->data)->u.odict;
        char* algorithm_str = NULL;
        enum rawrtc_certificate_sign_algorithm algorithm;
        char* value;

        // Get fingerprint
        error |= dict_get_entry(&algorithm_str, node, "algorithm", ODICT_STRING, true);
        error |= rawrtc_str_to_certificate_sign_algorithm(&algorithm, algorithm_str);
        error |= dict_get_entry(&value, node, "value", ODICT_STRING, true);
        if (error) {
            goto out;
        }

        // Create and add fingerprint
        error = rawrtc_dtls_fingerprint_create(&fingerprints->fingerprints[i], algorithm, value);
        if (error) {
            goto out;
        }
    }

    // Create DTLS parameters
    error = rawrtc_dtls_parameters_create(
            &parameters, role, fingerprints->fingerprints, fingerprints->n_fingerprints);

out:
    mem_deref(fingerprints);

    if (error) {
        mem_deref(parameters);
    } else {
        // Set pointer
        *parametersp = parameters;
    }
    return error;
}

/*
 * Get SCTP parameters from dictionary.
 */
enum rawrtc_code get_sctp_parameters(
        struct sctp_parameters* const parameters,
        struct odict* const dict
) {
    enum rawrtc_code error;
    uint64_t max_message_size;

    // Get maximum message size
    error = dict_get_entry(&max_message_size, dict, "maxMessageSize", ODICT_INT, true);
    if (error) {
        return error;
    }

    // Get port
    error = dict_get_uint16(&parameters->port, dict, "port", false);
    if (error && error != RAWRTC_CODE_NO_VALUE) {
        // Note: Nothing to do in NO VALUE case as port has been set to 0 by default
        return error;
    }

    // Create SCTP capabilities instance
    return rawrtc_sctp_capabilities_create(&parameters->capabilities, max_message_size);
}
