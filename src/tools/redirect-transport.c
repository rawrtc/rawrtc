#include <stdio.h>
#include <stdlib.h> // strtol
#include <string.h> // strerror
#include <unistd.h> // STDIN_FILENO
#include <rawrtc.h>
#include "../librawrtc/utils.h" /* TODO: Replace with <rawrtc_internal/utils.h> */

/* TODO: Replace with zf_log */
#define DEBUG_MODULE "redirect-transport-app"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

enum {
    PARAMETERS_MAX_LENGTH = 8192,
};

struct parameters {
    struct rawrtc_ice_parameters* ice_parameters;
    struct rawrtc_ice_candidates* ice_candidates;
    struct rawrtc_dtls_parameters* dtls_parameters;
};

struct client {
    char* name;
    struct rawrtc_ice_gather_options* gather_options;
    char* redirect_ip;
    uint16_t redirect_port;
    enum rawrtc_ice_role ice_role;
    struct rawrtc_certificate* certificate;
    struct rawrtc_ice_gatherer* gatherer;
    struct rawrtc_ice_transport* ice_transport;
    struct rawrtc_dtls_transport* dtls_transport;
    struct rawrtc_redirect_transport* redirect_transport;
    struct parameters local_parameters;
    struct parameters remote_parameters;
};

static bool str_to_uint16(
        uint16_t* const numberp,
        char* const str
) {
    char* end;
    int_least32_t number = (int_least32_t) strtol(str, &end, 10);

    // Don't ask, strtol is insane...
    if (number == 0 && str == end) {
        return false;
    }

    // Check bounds
    if (number < 0 || number > UINT16_MAX) {
        return false;
    }

    // Phew, we did it...
    *numberp = (uint16_t) number;
    return true;
}

static enum rawrtc_code dict_get_entry(
        void* const valuep,
        struct odict* const parent,
        char* const key,
        enum odict_type const type,
        bool required
) {
    struct odict_entry const * entry;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Do lookup
    entry = odict_lookup(parent, key);

    // Check for entry
    if (!entry) {
        if (required) {
            DEBUG_WARNING("'%s' missing\n", key);
            return RAWRTC_CODE_INVALID_ARGUMENT;
        } else {
            return RAWRTC_CODE_NO_VALUE;
        }
    }

    // Check for type
    if (entry->type != type) {
        DEBUG_WARNING("'%s' is of different type than expected\n", key);
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set value according to type
    switch (type) {
        case ODICT_OBJECT:
        case ODICT_ARRAY:
            *((struct odict** const) valuep) = entry->u.odict;
            break;
        case ODICT_STRING:
            *((char** const) valuep) = entry->u.str;
            break;
        case ODICT_INT:
            *((int64_t* const) valuep) = entry->u.integer;
            break;
        case ODICT_DOUBLE:
            *((double* const) valuep) = entry->u.dbl;
            break;
        case ODICT_BOOL:
            *((bool* const) valuep) = entry->u.boolean;
            break;
        case ODICT_NULL:
            *((char** const) valuep) = NULL; // meh!
            break;
        default:
            return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

static enum rawrtc_code dict_get_uint32(
        uint32_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT32_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    } else {
        *valuep = (uint32_t) value;
        return RAWRTC_CODE_SUCCESS;
    }
}

static enum rawrtc_code dict_get_uint16(
        uint16_t* const valuep,
        struct odict* const parent,
        char* const key,
        bool required
) {
    int64_t value;

    // Check arguments
    if (!valuep || !parent || !key) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get int64_t
    enum rawrtc_code error = dict_get_entry(&value, parent, key, ODICT_INT, required);
    if (error) {
        return error;
    }

    // Check bounds
    if (value < 0 || value > UINT16_MAX) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    } else {
        *valuep = (uint16_t) value;
        return RAWRTC_CODE_SUCCESS;
    }
}

static void client_print_local_parameters(
        struct client *client
);

static void ice_gatherer_state_change_handler(
        enum rawrtc_ice_gatherer_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_gatherer_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer state: %s\n", client->name, state_name);
}

static void ice_gatherer_error_handler(
        struct rawrtc_ice_candidate* const host_candidate, // read-only, nullable
        char const * const url, // read-only
        uint16_t const error_code, // read-only
        char const * const error_text, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) host_candidate; (void) error_code; (void) arg;
    DEBUG_PRINTF("(%s) ICE gatherer error, URL: %s, reason: %s\n", client->name, url, error_text);
}

static void ice_gatherer_local_candidate_handler(
        struct rawrtc_ice_candidate* const candidate,
        char const * const url, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) candidate; (void) arg;

    if (candidate) {
        DEBUG_PRINTF("(%s) ICE gatherer local candidate, URL: %s\n", client->name, url);
    } else {
        DEBUG_PRINTF("(%s) ICE gatherer last local candidate\n", client->name);
        // Print local parameters
        client_print_local_parameters(client);
    }
}

static void ice_transport_state_change_handler(
        enum rawrtc_ice_transport_state const state,
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_ice_transport_state_to_name(state);
    (void) arg;
    DEBUG_PRINTF("(%s) ICE transport state: %s\n", client->name, state_name);
}

static void ice_transport_candidate_pair_change_handler(
        struct rawrtc_ice_candidate* const local, // read-only
        struct rawrtc_ice_candidate* const remote, // read-only
        void* const arg
) {
    struct client* const client = arg;
    (void) local; (void) remote;
    DEBUG_PRINTF("(%s) ICE transport candidate pair change\n", client->name);
}

static void dtls_transport_state_change_handler(
        enum rawrtc_dtls_transport_state const state, // read-only
        void* const arg
) {
    struct client* const client = arg;
    char const * const state_name = rawrtc_dtls_transport_state_to_name(state);
    DEBUG_PRINTF("(%s) DTLS transport state change: %s\n", client->name, state_name);
}

static void dtls_transport_error_handler(
        /* TODO: error.message (probably from OpenSSL) */
        void* const arg
) {
    struct client* const client = arg;
    // TODO: Print error message
    DEBUG_PRINTF("(%s) DTLS transport error: %s\n", client->name, "???");
}

static void signal_handler(
        int sig
) {
    DEBUG_INFO("Got signal: %d, terminating...\n", sig);
    re_cancel();
}

static void client_init(
        struct client* const client
) {
    // Generate certificates
    EOE(rawrtc_certificate_generate(&client->certificate, NULL));
    struct rawrtc_certificate* certificates[] = {client->certificate};

    // Create ICE gatherer
    EOE(rawrtc_ice_gatherer_create(
            &client->gatherer, client->gather_options,
            ice_gatherer_state_change_handler, ice_gatherer_error_handler,
            ice_gatherer_local_candidate_handler, client));

    // Create ICE transport
    EOE(rawrtc_ice_transport_create(
            &client->ice_transport, client->gatherer,
            ice_transport_state_change_handler, ice_transport_candidate_pair_change_handler,
            client));

    // Create DTLS transport
    EOE(rawrtc_dtls_transport_create(
            &client->dtls_transport, client->ice_transport, certificates,
            sizeof(certificates) / sizeof(certificates[0]),
            dtls_transport_state_change_handler, dtls_transport_error_handler, client));

    // Create redirect transport
    EOE(rawrtc_redirect_transport_create(
            &client->redirect_transport, client->dtls_transport,
            client->redirect_ip, client->redirect_port, 0, 0));
}

static void client_start_gathering(
        struct client* const client
) {
    // Start gathering
    EOE(rawrtc_ice_gatherer_gather(client->gatherer, NULL));
}

static void client_get_parameters(
        struct client* const client
) {
    struct parameters* const local_parameters = &client->local_parameters;

    // Get local ICE parameters
    EOE(rawrtc_ice_gatherer_get_local_parameters(
            &local_parameters->ice_parameters, client->gatherer));

    // Get local ICE candidates
    EOE(rawrtc_ice_gatherer_get_local_candidates(
            &local_parameters->ice_candidates, client->gatherer));

    // Get local DTLS parameters
    EOE(rawrtc_dtls_transport_get_local_parameters(
            &local_parameters->dtls_parameters, client->dtls_transport));
}

static void client_set_parameters(
        struct client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Set remote ICE candidates
    EOE(rawrtc_ice_transport_set_remote_candidates(
            client->ice_transport, remote_parameters->ice_candidates->candidates,
            remote_parameters->ice_candidates->n_candidates));
}

static void client_start_transports(
        struct client* const client
) {
    struct parameters* const remote_parameters = &client->remote_parameters;

    // Start ICE transport
    EOE(rawrtc_ice_transport_start(
            client->ice_transport, client->gatherer, remote_parameters->ice_parameters,
            client->ice_role));

    // Start DTLS transport
    EOE(rawrtc_dtls_transport_start(
            client->dtls_transport, remote_parameters->dtls_parameters));
}

static void parameters_destroy(
        struct parameters* const parameters
) {
    // Dereference
    parameters->ice_parameters = mem_deref(parameters->ice_parameters);
    parameters->ice_candidates = mem_deref(parameters->ice_candidates);
    parameters->dtls_parameters = mem_deref(parameters->dtls_parameters);
}

static void client_stop(
        struct client* const client
) {
    client->redirect_transport = mem_deref(client->redirect_transport);
    EOE(rawrtc_dtls_transport_stop(client->dtls_transport));
    EOE(rawrtc_ice_transport_stop(client->ice_transport));
    EOE(rawrtc_ice_gatherer_close(client->gatherer));

    // Dereference & close
    parameters_destroy(&client->remote_parameters);
    parameters_destroy(&client->local_parameters);
    client->dtls_transport = mem_deref(client->dtls_transport);
    client->ice_transport = mem_deref(client->ice_transport);
    client->gatherer = mem_deref(client->gatherer);
    client->certificate = mem_deref(client->certificate);
    client->gather_options = mem_deref(client->gather_options);

    // Stop listening on STDIN
    fd_close(STDIN_FILENO);
}

static void client_set_ice_parameters(
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

    // Dereference values
    mem_deref(password);
    mem_deref(username_fragment);
}

static void client_set_ice_candidates(
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
        EOR(odict_entry_add(node, "priority", ODICT_INT, priority));
        EOR(odict_entry_add(node, "ip", ODICT_STRING, ip));
        EOR(odict_entry_add(node, "protocol", ODICT_STRING, rawrtc_ice_protocol_to_str(protocol)));
        EOR(odict_entry_add(node, "port", ODICT_INT, port));
        EOR(odict_entry_add(node, "type", ODICT_STRING, rawrtc_ice_candidate_type_to_str(type)));
        if (type == RAWRTC_ICE_PROTOCOL_TCP) {
            EOR(odict_entry_add(node, "tcpType", ODICT_STRING,
                                rawrtc_ice_tcp_candidate_type_to_str(tcp_type)));
        }
        if (related_address) {
            EOR(odict_entry_add(node, "relatedAddress", ODICT_STRING, related_address));
        }
        if (related_port) {
            EOR(odict_entry_add(node, "relatedPort", ODICT_INT, related_port));
        }

        // Add to array
        EOE(rawrtc_sdprintf(&key, "%zu", i));
        EOR(odict_entry_add(array, key, ODICT_OBJECT, node));

        // Dereference values
        mem_deref(key);
        mem_deref(related_address);
        mem_deref(ip);
        mem_deref(foundation);
        mem_deref(node);
    }
}

static void client_set_dtls_parameters(
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
    for (i = 0; i < parameters->fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint =
                parameters->fingerprints->fingerprints[i];
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

        // Dereference values
        mem_deref(key);
        mem_deref(value);
        mem_deref(node);
    }

    // Dereference fingerprints
    mem_deref(fingerprints);

    // Add array to object
    EOR(odict_entry_add(dict, "fingerprints", ODICT_ARRAY, array));
    mem_deref(array);
}

static void client_print_local_parameters(
        struct client *client
) {
    struct odict* dict;
    struct odict* node;

    // Get local parameters
    client_get_parameters(client);

    // Create dict
    EOR(odict_alloc(&dict, 16));

    // Create nodes
    EOR(odict_alloc(&node, 16));
    client_set_ice_parameters(client->local_parameters.ice_parameters, node);
    EOR(odict_entry_add(dict, "iceParameters", ODICT_OBJECT, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    client_set_ice_candidates(client->local_parameters.ice_candidates, node);
    EOR(odict_entry_add(dict, "iceCandidates", ODICT_ARRAY, node));
    mem_deref(node);
    EOR(odict_alloc(&node, 16));
    client_set_dtls_parameters(client->local_parameters.dtls_parameters, node);
    EOR(odict_entry_add(dict, "dtlsParameters", ODICT_OBJECT, node));
    mem_deref(node);

    // Print JSON
    DEBUG_INFO("Local Parameters:\n%H\n", json_encode_odict, dict);

    // Dereference
    mem_deref(dict);
}

static enum rawrtc_code client_get_ice_parameters(
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

static void client_ice_candidates_destroy(
        void* const arg
) {
    struct rawrtc_ice_candidates* const candidates = arg;
    size_t i;

    // Dereference each item
    for (i = 0; i < candidates->n_candidates; ++i) {
        mem_deref(candidates->candidates[i]);
    }
}

static enum rawrtc_code client_get_ice_candidates(
        struct rawrtc_ice_candidates** const candidatesp,
        struct odict* const dict
) {
    size_t n;
    struct rawrtc_ice_candidates* candidates;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct le* le;
    size_t i;

    // Get length
    n = list_count(&dict->lst);

    // Allocate & set length immediately
    candidates = mem_zalloc(sizeof(*candidates) + (sizeof(struct rawrtc_ice_candidate*) * n),
                            client_ice_candidates_destroy);
    if (!candidates) {
        EWE("No memory to allocate ICE candidates array");
    }
    candidates->n_candidates = n;

    // Get ICE candidates
    for (le = list_head(&dict->lst), i = 0; le != NULL; le = le->next, ++i) {
        struct odict* const node = ((struct odict_entry*) le->data)->u.odict;
        char* foundation;
        uint32_t priority;
        char* ip;
        char const* protocol_str = NULL;
        enum rawrtc_ice_protocol protocol;
        uint16_t port;
        char const* type_str = NULL;
        enum rawrtc_ice_candidate_type type;
        char const* tcp_type_str = NULL;
        enum rawrtc_ice_tcp_candidate_type tcp_type = RAWRTC_ICE_TCP_CANDIDATE_TYPE_ACTIVE;
        char* related_address = NULL;
        uint16_t related_port = 0;

        // Get ICE candidate
        error |= dict_get_entry(&foundation, node, "foundation", ODICT_STRING, true);
        error |= dict_get_uint32(&priority, node, "priority", true);
        error |= dict_get_entry(&ip, node, "ip", ODICT_STRING, true);
        error |= dict_get_entry(&protocol_str, node, "protocol", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_protocol(&protocol, protocol_str);
        error |= dict_get_uint16(&port, node, "port", true);
        error |= dict_get_entry(&type_str, node, "type", ODICT_STRING, true);
        error |= rawrtc_str_to_ice_candidate_type(&type, type_str);
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
                &candidates->candidates[i], foundation, priority, ip, protocol, port, type,
                tcp_type, related_address, related_port);
        if (error) {
            goto out;
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

static void client_dtls_fingerprints_destroy(
        void* const arg
) {
    struct rawrtc_dtls_fingerprints* const fingerprints = arg;
    size_t i;

    // Dereference each item
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        mem_deref(fingerprints->fingerprints[i]);
    }
}

static enum rawrtc_code client_get_dtls_parameters(
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
            client_dtls_fingerprints_destroy);
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

static void client_stdin_handler(
        int flags,
        void* const arg
) {
    struct client* const client = arg;
    char buffer[PARAMETERS_MAX_LENGTH];
    size_t length;
    bool do_exit = false;
    struct odict* dict = NULL;
    struct odict* node = NULL;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;
    struct rawrtc_ice_parameters* ice_parameters = NULL;
    struct rawrtc_ice_candidates* ice_candidates = NULL;
    struct rawrtc_dtls_parameters* dtls_parameters = NULL;
    (void) flags;

    // Get message from stdin
    if (!fgets((char*) buffer, PARAMETERS_MAX_LENGTH, stdin)) {
        EWE("Error polling stdin");
    }
    length = strlen(buffer);

    // Exit?
    if (length == 1 && buffer[0] == '\n') {
        do_exit = true;
        DEBUG_NOTICE("Exiting\n");
        goto out;
    }

    // Decode JSON
    EOR(json_decode_odict(&dict, 16, buffer, length, 3));
    error |= dict_get_entry(&node, dict, "iceParameters", ODICT_OBJECT, true);
    error |= client_get_ice_parameters(&ice_parameters, node);
    error |= dict_get_entry(&node, dict, "iceCandidates", ODICT_ARRAY, true);
    error |= client_get_ice_candidates(&ice_candidates, node);
    error |= dict_get_entry(&node, dict, "dtlsParameters", ODICT_OBJECT, true);
    error |= client_get_dtls_parameters(&dtls_parameters, node);

    // Ok?
    if (error) {
        DEBUG_WARNING("Invalid remote parameters\n");
        goto out;
    }

    // Set parameters & start transports
    client->remote_parameters.ice_parameters = mem_ref(ice_parameters);
    client->remote_parameters.ice_candidates = mem_ref(ice_candidates);
    client->remote_parameters.dtls_parameters = mem_ref(dtls_parameters);
    DEBUG_INFO("Applying remote parameters\n");
    client_set_parameters(client);
    client_start_transports(client);
    
out:
    mem_deref(dtls_parameters);
    mem_deref(ice_candidates);
    mem_deref(ice_parameters);
    mem_deref(dict);
    
    // Exit?
    if (do_exit) {
        // Stop client & bye
        client_stop(client);
        rawrtc_before_exit();
        exit(0);
    }
}

static void exit_with_usage(char* program) {
    DEBUG_WARNING("Usage: %s <0|1 (ice-role)> <redirect-ip> <redirect-port>", program);
    exit(1);
}

int main(int argc, char* argv[argc + 1]) {
    enum rawrtc_ice_role ice_role;
    uint16_t redirect_port;
    struct rawrtc_ice_gather_options* gather_options;
    char* const stun_google_com_urls[] = {"stun.l.google.com:19302", "stun1.l.google.com:19302"};
    char* const turn_zwuenf_org_urls[] = {"turn.zwuenf.org"};
    struct client client = {0};

    // Initialise
    EOE(rawrtc_init());

    // Debug
    // TODO: This should be replaced by our own debugging system
    dbg_init(DBG_DEBUG, DBG_ALL);
    DEBUG_PRINTF("Init\n");

    // Check arguments length
    if (argc < 4) {
        exit_with_usage(argv[0]);
    }

    // Get ICE role
    switch (argv[1][0]) {
        case '0':
            ice_role = RAWRTC_ICE_ROLE_CONTROLLED;
            break;
        case '1':
            ice_role = RAWRTC_ICE_ROLE_CONTROLLING;
            break;
        default:
            exit_with_usage(argv[0]);
            return 1;
    }

    // Get redirect port
    if (!str_to_uint16(&redirect_port, argv[3])) {
        exit_with_usage(argv[0]);
    }

    // Create ICE gather options
    EOE(rawrtc_ice_gather_options_create(&gather_options, RAWRTC_ICE_GATHER_ALL));

    // Add ICE servers to ICE gather options
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, stun_google_com_urls,
            sizeof(stun_google_com_urls) / sizeof(stun_google_com_urls[0]),
            NULL, NULL, RAWRTC_ICE_CREDENTIAL_NONE));
    EOE(rawrtc_ice_gather_options_add_server(
            gather_options, turn_zwuenf_org_urls,
            sizeof(turn_zwuenf_org_urls) / sizeof(turn_zwuenf_org_urls[0]),
            "bruno", "onurb", RAWRTC_ICE_CREDENTIAL_PASSWORD));

    // Set client fields
    client.name = "A";
    client.gather_options = gather_options;
    client.ice_role = ice_role;
    client.redirect_ip = argv[2];
    client.redirect_port = redirect_port;

    // Setup client
    client_init(&client);

    // Start gathering
    client_start_gathering(&client);

    // Listen on stdin
    EOR(fd_listen(STDIN_FILENO, FD_READ, client_stdin_handler, &client));

    // Start main loop
    // TODO: Wrap re_main?
    // TODO: Stop main loop once gathering is complete
    EOE(rawrtc_error_to_code(re_main(signal_handler)));

    // Stop client & bye
    client_stop(&client);
    rawrtc_before_exit();
    return 0;
}
