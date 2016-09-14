#include <anyrtc.h>
#include "utils.h"
#include "ice_gatherer.h"

static void anyrtc_ice_gather_options_destroy(void* arg) {
    struct anyrtc_ice_gather_options* options = arg;

    // Dereference
    list_flush(&options->ice_servers);
}

/*
 * Create a new ICE gather options.
 */
enum anyrtc_code anyrtc_ice_gather_options_create(
        struct anyrtc_ice_gather_options** const optionsp, // de-referenced
        enum anyrtc_ice_gather_policy const gather_policy
) {
    struct anyrtc_ice_gather_options* options;

    // Check arguments
    if (!optionsp) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    options = mem_alloc(sizeof(struct anyrtc_ice_gather_options),
                        anyrtc_ice_gather_options_destroy);
    if (!options) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    options->gather_policy = gather_policy;
    list_init(&options->ice_servers);

    // Set pointer and return
    *optionsp = options;
    return ANYRTC_CODE_SUCCESS;
}

static void anyrtc_ice_server_url_destroy(void* arg) {
    struct anyrtc_ice_server_url* url = arg;

    // Dereference
    mem_deref(url->url);
}

static enum anyrtc_code anyrtc_ice_server_url_create(
        struct anyrtc_ice_server_url** const urlp, // de-referenced
        char* const url_s // copied
) {
    struct anyrtc_ice_server_url* url;
    enum anyrtc_code error;
    char* copy;

    // Check arguments
    if (!urlp || !url_s) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    url = mem_zalloc(sizeof(struct anyrtc_ice_server_url), anyrtc_ice_server_url_destroy);
    if (!url) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Copy URL
    error = anyrtc_strdup(&copy, url_s);
    if (error) {
        mem_deref(url);
        return error;
    }

    // Set pointer and return
    url->url = copy;
    *urlp = url;
    return ANYRTC_CODE_SUCCESS;
}

static void anyrtc_ice_server_destroy(void* arg) {
    struct anyrtc_ice_server* server = arg;

    // Dereference
    list_flush(&server->urls);
    mem_deref(server->username);
    mem_deref(server->credential);
}

/*
 * Add an ICE server to the gather options.
 */
enum anyrtc_code anyrtc_ice_gather_options_add_server(
        struct anyrtc_ice_gather_options* const options,
        char* const * const urls, // copied
        size_t const n_urls,
        char* const username, // nullable, copied
        char* const credential, // nullable, copied
        enum anyrtc_ice_credential_type const credential_type
) {
    struct anyrtc_ice_server* server;
    enum anyrtc_code error = ANYRTC_CODE_SUCCESS;
    size_t i;

    // Check arguments
    if (!options || !urls) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    server = mem_zalloc(sizeof(struct anyrtc_ice_server), anyrtc_ice_server_destroy);
    if (!server) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Copy URLs to list
    list_init(&server->urls);
    for (i = 0; i < n_urls; ++i) {
        struct anyrtc_ice_server_url* url;

        // Ensure URLs aren't null
        if (!urls[i]) {
            error = ANYRTC_CODE_INVALID_ARGUMENT;
            goto out;
        }

        // Copy URL
        error = anyrtc_ice_server_url_create(&url, urls[i]);
        if (error) {
            goto out;
        }

        // Append URL to list
        list_append(&server->urls, &url->le, url);
    }

    // Set fields
    if (credential_type != ANYRTC_ICE_CREDENTIAL_NONE) {
        if (username) {
            error = anyrtc_strdup(&server->username, username);
            if (error) {
                goto out;
            }
        }
        if (credential) {
            error = anyrtc_strdup(&server->credential, credential);
            if (error) {
                goto out;
            }
        }
    }
    server->credential_type = credential_type; // TODO: Validation needed in case TOKEN is used?

    // Add to options
    list_append(&options->ice_servers, &server->le, server);

out:
    if (error) {
        list_flush(&server->urls);
        mem_deref(server->username);
        mem_deref(server->credential);
        mem_deref(server);
    }
    return error;
}

static void anyrtc_ice_gatherer_destroy(void* arg) {
    struct anyrtc_ice_gatherer* gatherer = arg;

    // Dereference
    mem_deref(gatherer->options);
}

/*
 * Create a new ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_create(
        struct anyrtc_ice_gatherer** const gathererp, // de-referenced
        struct anyrtc_ice_gather_options* const options, // referenced
        anyrtc_ice_gatherer_state_change_handler* const state_change_handler, // nullable
        anyrtc_ice_gatherer_error_handler* const error_handler, // nullable
        anyrtc_ice_gatherer_local_candidate_handler* const local_candidate_handler, // nullable
        void* const arg // nullable
) {
    struct anyrtc_ice_gatherer* gatherer;

    // Check arguments
    if (!gathererp || !options) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate
    gatherer = mem_alloc(sizeof(struct anyrtc_ice_gatherer), anyrtc_ice_gatherer_destroy);
    if (!gatherer) {
        return ANYRTC_CODE_NO_MEMORY;
    }

    // Set fields/reference
    gatherer->state = ANYRTC_ICE_GATHERER_NEW;
    gatherer->options = mem_ref(options);
    gatherer->state_change_handler = state_change_handler;
    gatherer->error_handler = error_handler;
    gatherer->local_candidate_handler = local_candidate_handler;
    gatherer->arg = arg;

    // Set pointer and return
    *gathererp = gatherer;
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}

/*
 * Close the ICE gatherer.
 */
enum anyrtc_code anyrtc_ice_gatherer_close(
        struct anyrtc_ice_gatherer* const gatherer
) {
    // Check arguments
    if (!gatherer) {
        return ANYRTC_CODE_INVALID_ARGUMENT;
    }

    // Set state to closed and return
    gatherer->state = ANYRTC_ICE_GATHERER_CLOSED;
    return ANYRTC_CODE_NOT_IMPLEMENTED;
}
