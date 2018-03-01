#include <string.h> // strlen
#include <rawrtcdc/internal/sctp_capabilities.h>
#include <rawrtc.h>
#include "ice_parameters.h"
#include "dtls_parameters.h"
#include "peer_connection.h"
#include "peer_connection_configuration.h"
#include "peer_connection_description.h"
#include "peer_connection_ice_candidate.h"

#define DEBUG_MODULE "peer-connection-description"
//#define RAWRTC_DEBUG_MODULE_LEVEL 7 // Note: Uncomment this to debug this module only
#include <rawrtcc/internal/debug.h>

// Constants
static uint16_t const discard_port = 9;
static char const sdp_application_dtls_sctp_regex[] = "application [0-9]+ [^ ]+";
static char const * const sdp_application_dtls_sctp_variants[] = {
    "DTLS/SCTP",
    "UDP/DTLS/SCTP",
    "TCP/DTLS/SCTP",
};
static size_t const sdp_application_dtls_sctp_variants_length =
        ARRAY_SIZE(sdp_application_dtls_sctp_variants);
static char const sdp_group_regex[] = "group:BUNDLE [^]+";
static char const sdp_mid_regex[] = "mid:[^]+";
static char const sdp_ice_options_trickle[] = "ice-options:trickle";
static char const sdp_ice_username_fragment_regex[] = "ice-ufrag:[^]+";
static char const sdp_ice_password_regex[] = "ice-pwd:[^]+";
static char const sdp_ice_lite[] = "ice-lite";
static char const sdp_dtls_role_regex[] = "setup:[^]+";
static enum rawrtc_dtls_role const map_enum_dtls_role[] = {
    RAWRTC_DTLS_ROLE_AUTO,
    RAWRTC_DTLS_ROLE_CLIENT,
    RAWRTC_DTLS_ROLE_SERVER,
};
static char const * const map_str_dtls_role[] = {
    "actpass"
    "active",
    "passive",
};
static size_t const map_dtls_role_length =
        ARRAY_SIZE(map_enum_dtls_role);
static char const sdp_dtls_fingerprint_regex[] = "fingerprint:[^ ]+ [^]+";
static char const sdp_sctp_port_sctmap_regex[] = "sctpmap:[0-9]+[^]*";
static char const sdp_sctp_port_regex[] = "sctp-port:[0-9]+";
static char const sdp_sctp_maximum_message_size_regex[] = "max-message-size:[0-9]+";
static char const sdp_ice_end_of_candidates[] = "end-of-candidates";
static char const sdp_ice_candidate_head[] = "candidate:";
static size_t const sdp_ice_candidate_head_length = ARRAY_SIZE(sdp_ice_candidate_head);

// Candidate line
struct candidate_line {
    struct le le;
    struct pl line;
};

/*
 * Set session boilerplate
 */
static enum rawrtc_code set_session_boilerplate(
        struct mbuf* const sdp, // not checked
        char const* const version, // not checked
        uint32_t const id
) {
    int err;

    // Write session boilerplate
    err = mbuf_write_str(sdp, "v=0\r\n");
    err |= mbuf_printf(
            sdp, "o=sdpartanic-rawrtc-%s %"PRIu32" 1 IN IP4 127.0.0.1\r\n", version, id);
    err |= mbuf_write_str(sdp, "s=-\r\n");
    err |= mbuf_write_str(sdp, "t=0 0\r\n");

    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Set session attributes on SDP.
 */
static enum rawrtc_code set_session_attributes(
        struct mbuf* const sdp, // not checked
        bool const trickle_ice,
        char const* const bundled_mids
) {
    int err = 0;

    // Trickle ICE
    if (trickle_ice) {
        err = mbuf_write_str(sdp, "a=ice-options:trickle\r\n");
    }

    // WebRTC identity not supported as of now

    // Bundle media (we currently only support a single SCTP transport and nothing else)
    if (bundled_mids) {
        err |= mbuf_printf(sdp, "a=group:BUNDLE %s\r\n", bundled_mids);
    }

    // Done
    return rawrtc_error_to_code(err);
}

/*
 * Get general attributes from an SDP line.
 */
static enum rawrtc_code get_general_attributes(
        char** const bundled_midsp, // de-referenced, not checked
        char** const midp, // de-referenced, not checked
        struct pl* const line // not checked
) {
    enum rawrtc_code error;
    struct pl value;

    // Bundle groups
    if (!re_regex(line->p, line->l, sdp_group_regex, &value)) {
        // Check if there is more than one group
        if (pl_strchr(&value, ' ')) {
            DEBUG_WARNING("Only one bundle group is supported\n");
            error = RAWRTC_CODE_NOT_IMPLEMENTED;
            return error;
        }

        // Copy group
        error = rawrtc_error_to_code(pl_strdup(bundled_midsp, &value));
        if (error) {
            DEBUG_WARNING("Couldn't copy bundle group\n");
            return error;
        }
    }

    // Media line identification tag
    if (!re_regex(line->p, line->l, sdp_mid_regex, &value)) {
        // Copy 'mid'
        error = rawrtc_error_to_code(pl_strdup(midp, &value));
        if (error) {
            DEBUG_WARNING("Couldn't copy 'mid'\n");
            return error;
        }
    }

    // Done
    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Add ICE attributes to SDP media line.
 */
static enum rawrtc_code add_ice_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_peer_connection_context* const context // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_ice_parameters* parameters;
    char* username_fragment = NULL;
    char* password = NULL;
    int err;

    // Get ICE parameters
    error = rawrtc_ice_gatherer_get_local_parameters(&parameters, context->ice_gatherer);
    if (error) {
        return error;
    }

    // Get values
    error = rawrtc_ice_parameters_get_username_fragment(&username_fragment, parameters);
    error |= rawrtc_ice_parameters_get_password(&password, parameters);
    if (error) {
        goto out;
    }

    // Set username fragment and password
    err = mbuf_printf(sdp, "a=ice-ufrag:%s\r\n", username_fragment);
    err |= mbuf_printf(sdp, "a=ice-pwd:%s\r\n", password);
    error = rawrtc_error_to_code(err);

out:
    mem_deref(password);
    mem_deref(username_fragment);
    mem_deref(parameters);
    return error;
}

/*
 * Get ICE attributes from SDP line.
 */
static enum rawrtc_code get_ice_attributes(
        bool* const trickle_icep, // de-referenced, not checked
        char** const username_fragmentp, // de-referenced, not checked
        char** const passwordp, // de-referenced, not checked
        bool* const ice_litep, // de-referenced, not checked
        struct pl* const line // not checked
) {
    struct pl value;

    // ICE options trickle
    if (pl_strcmp(line, sdp_ice_options_trickle) == 0) {
        *trickle_icep = true;
        return RAWRTC_CODE_SUCCESS;
    }

    // ICE username fragment
    if (!re_regex(line->p, line->l, sdp_ice_username_fragment_regex, &value)) {
        return rawrtc_sdprintf(username_fragmentp, "%r", &value);
    }

    // ICE password
    if (!re_regex(line->p, line->l, sdp_ice_password_regex, &value)) {
        return rawrtc_sdprintf(passwordp, "%r", &value);
    }

    // ICE lite
    if (pl_strcmp(line, sdp_ice_lite) == 0) {
        *ice_litep = true;
        return RAWRTC_CODE_SUCCESS;
    }

    // Done
    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Add DTLS fingerprint attributes to SDP media line.
 */
static enum rawrtc_code add_dtls_fingerprint_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_dtls_parameters* const parameters // not checked
) {
    enum rawrtc_code error;
    struct rawrtc_dtls_fingerprints* fingerprints;
    size_t i;
    char* value = NULL;

    // Get fingerprints
    error = rawrtc_dtls_parameters_get_fingerprints(&fingerprints, parameters);
    if (error) {
        return error;
    }

    // Add fingerprints
    for (i = 0; i < fingerprints->n_fingerprints; ++i) {
        struct rawrtc_dtls_fingerprint* const fingerprint = fingerprints->fingerprints[i];
        enum rawrtc_certificate_sign_algorithm sign_algorithm;

        // Get sign algorithm
        error = rawrtc_dtls_parameters_fingerprint_get_sign_algorithm(&sign_algorithm, fingerprint);
        if (error) {
            goto out;
        }

        // Get fingerprint value
        error = rawrtc_dtls_parameters_fingerprint_get_value(&value, fingerprint);
        if (error) {
            goto out;
        }

        // Add fingerprint attribute
        error = rawrtc_error_to_code(mbuf_printf(
                sdp, "a=fingerprint:%s %s\r\n",
                rawrtc_certificate_sign_algorithm_to_str(sign_algorithm), value));
        if (error) {
            goto out;
        }
    }

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference
    mem_deref(value);
    mem_deref(fingerprints);
    return error;
}

/*
 * Get DTLS fingerprint attribute from an SDP line.
 */
static enum rawrtc_code get_dtls_fingerprint_attributes(
        struct rawrtc_dtls_fingerprint** const fingerprintp, // de-referenced, not checked
        struct pl* const line // not checked
) {
    struct pl algorithm_pl;
    struct pl value_pl;
    enum rawrtc_code error;
    char* algorithm_str = NULL;
    char* value_str = NULL;
    enum rawrtc_certificate_sign_algorithm algorithm;

    // Parse DTLS fingerprint
    if (re_regex(line->p, line->l, sdp_dtls_fingerprint_regex, &algorithm_pl, &value_pl)) {
        return RAWRTC_CODE_NO_VALUE;
    }

    // Copy certificate sign algorithm and value to string
    error = rawrtc_sdprintf(&algorithm_str, "%r", &algorithm_pl);
    if (error) {
        goto out;
    }
    error = rawrtc_sdprintf(&value_str, "%r", &value_pl);
    if (error) {
        goto out;
    }

    // Convert certificate sign algorithm
    error = rawrtc_str_to_certificate_sign_algorithm(&algorithm, algorithm_str);
    if (error) {
        // This is allowed to fail, some people still use SHA-1 and we don't support it. But there
        // may be further fingerprints.
        DEBUG_WARNING("Unsupported certificate sign algorithm: %r\n", &algorithm_pl);
        error = RAWRTC_CODE_NO_VALUE;
        goto out;
    }

    // Create DTLS fingerprint
    error = rawrtc_dtls_fingerprint_create(fingerprintp, algorithm, value_str);
    if (error) {
        goto out;
    }

out:
    // Un-reference
    mem_deref(value_str);
    mem_deref(algorithm_str);
    return error;
}

/*
 * Add DTLS transport attributes to SDP media line.
 */
static enum rawrtc_code add_dtls_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
        bool const offering
) {
    enum rawrtc_code error;
    struct rawrtc_dtls_parameters* parameters;
    enum rawrtc_dtls_role role;
    char const* setup_str;

    // Get DTLS parameters
    error = rawrtc_dtls_transport_get_local_parameters(&parameters, context->dtls_transport);
    if (error) {
        return error;
    }

    // Get DTLS role
    error = rawrtc_dtls_parameters_get_role(&role, parameters);
    if (error) {
        goto out;
    }

    // Add setup attribute
    if (offering) {
        // Note: When offering, we MUST use 'actpass' as specified in JSEP
        setup_str = "actpass";
    } else {
        switch (role) {
            case RAWRTC_DTLS_ROLE_AUTO:
                setup_str = "active";
                break;
            case RAWRTC_DTLS_ROLE_CLIENT:
                setup_str = "active";
                break;
            case RAWRTC_DTLS_ROLE_SERVER:
                setup_str = "passive";
                break;
            default:
                error = RAWRTC_CODE_INVALID_STATE;
                goto out;
                break;
        }
    }
    error = rawrtc_error_to_code(mbuf_printf(sdp, "a=setup:%s\r\n", setup_str));
    if (error) {
        goto out;
    }

    // Add fingerprints
    error = add_dtls_fingerprint_attributes(sdp, parameters);
    if (error) {
        goto out;
    }

    // Add (D)TLS ID
    error = rawrtc_error_to_code(mbuf_printf(sdp, "a=tls-id:%s\r\n", context->dtls_id));
    if (error) {
        goto out;
    }

out:
    mem_deref(parameters);
    return error;
}

/*
 * Get DTLS transport attribute from an SDP line.
 */
static enum rawrtc_code get_dtls_attributes(
        enum rawrtc_dtls_role* const rolep, // de-referenced, not checked
        struct list* const fingerprints, // not checked
        struct pl* const line // not checked
) {
    enum rawrtc_code error;
    struct pl role_pl;
    struct rawrtc_dtls_fingerprint* fingerprint;

    // DTLS role
    if (!re_regex(line->p, line->l, sdp_dtls_role_regex, &role_pl)) {
        size_t i;
        for (i = 0; i < map_dtls_role_length; ++i) {
            if (pl_strcmp(&role_pl, map_str_dtls_role[i]) == 0) {
                *rolep = map_enum_dtls_role[i];
                return RAWRTC_CODE_SUCCESS;
            }
        }
    }

    // DTLS fingerprint
    error = get_dtls_fingerprint_attributes(&fingerprint, line);
    if (!error) {
        list_append(fingerprints, &fingerprint->le, fingerprint);
    }
    return error;
}

/*
 * Add SCTP transport attributes to SDP session.
 */
static enum rawrtc_code add_sctp_attributes(
        struct mbuf* const sdp, // not checked
        struct rawrtc_sctp_transport* const transport, // not checked
        struct rawrtc_peer_connection_context* const context, // not checked
        bool const offering,
        char const* const remote_media_line,
        char const* const mid,
        bool const sctp_sdp_05
) {
    enum rawrtc_code error;
    uint16_t sctp_port;
    uint16_t sctp_n_streams;
    int err;

    // Get SCTP port
    error = rawrtc_sctp_transport_get_port(&sctp_port, transport);
    if (error) {
        return error;
    }

    // Get SCTP #streams
    error = rawrtc_sctp_transport_get_n_streams(&sctp_n_streams, transport);
    if (error) {
        return error;
    }

    // Add media section
    if (remote_media_line) {
        // Just repeat the remote media line.
        err = mbuf_printf(sdp, "m=%s\r\n", remote_media_line);
    } else {
        if (!sctp_sdp_05) {
            // Note: We choose UDP here although communication may still happen over ICE-TCP
            //       candidates.
            // See also: https://tools.ietf.org/html/draft-ietf-mmusic-sctp-sdp-25#section-12.2
            err = mbuf_printf(
                    sdp, "m=application %"PRIu16" UDP/DTLS/SCTP webrtc-datachannel\r\n",
                    discard_port);
        } else {
            err = mbuf_printf(
                    sdp, "m=application %"PRIu16" DTLS/SCTP %"PRIu16"\r\n",
                    discard_port, sctp_port);
        }
    }
    // Add dummy 'c'-line
    err |= mbuf_write_str(sdp, "c=IN IP4 0.0.0.0\r\n");
    // Add 'mid' line (if any)
    if (mid) {
        err |= mbuf_printf(sdp, "a=mid:%s\r\n", mid);
    }
    // Add direction line
    err |= mbuf_write_str(sdp, "a=sendrecv\r\n");
    if (err) {
        return rawrtc_error_to_code(err);
    }

    // Add ICE attributes
    error = add_ice_attributes(sdp, context);
    if (error) {
        return error;
    }

    // Add DTLS attributes
    error = add_dtls_attributes(sdp, context, offering);
    if (error) {
        return error;
    }

    // Set attributes
    if (!sctp_sdp_05) {
        // Set SCTP port
        // Note: Last time I checked, Chrome wasn't able to cope with this
        err = mbuf_printf(sdp, "a=sctp-port:%"PRIu16"\r\n", sctp_port);
    } else {
        // Set SCTP port, upper layer protocol and number of streams
        err = mbuf_printf(
                sdp, "a=sctpmap:%"PRIu16" webrtc-datachannel %"PRIu16"\r\n",
                sctp_port, sctp_n_streams);
    }
    if (err) {
        return rawrtc_error_to_code(err);
    }

    // Set maximum message size
    // Note: This isn't part of the 05 version but Firefox can only parse 'max-message-size' but
    //       doesn't understand the old 'sctpmap' one (from 06 to 21).
    err = mbuf_write_str(sdp, "a=max-message-size:0\r\n");
    error = rawrtc_error_to_code(err);
    if (error) {
        return error;
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get SCTP transport attributes from an SDP line.
 */
static enum rawrtc_code get_sctp_attributes(
        uint16_t* const portp, // de-referenced, not checked
        uint64_t* const max_message_sizep, // de-referenced, not checked
        struct pl* const line // not checked
) {
    struct pl port_pl;
    uint32_t port;
    struct pl max_message_size_pl;

    // SCTP port (from 'sctpmap' or 'sctp-port')
    if (!re_regex(line->p, line->l, sdp_sctp_port_sctmap_regex, &port_pl, NULL)
        || !re_regex(line->p, line->l, sdp_sctp_port_regex, &port_pl)) {
        port = pl_u32(&port_pl);

        // Validate port
        if (port == 0 || port > UINT16_MAX) {
            DEBUG_WARNING("Invalid SCTP port: %"PRIu32"\n", port);
            return RAWRTC_CODE_INVALID_ARGUMENT;
        }

        // Set port & done
        *portp = (uint16_t) port;
        return RAWRTC_CODE_SUCCESS;
    }

    // SCTP maximum message size
    // Note: Theoretically, there's another approach as part of 'sctmap' which has been deprecated
    //       but I doubt anyone ever implemented that.
    if (!re_regex(line->p, line->l, sdp_sctp_maximum_message_size_regex, &max_message_size_pl)) {
        *max_message_sizep = pl_u64(&max_message_size_pl);
        return RAWRTC_CODE_SUCCESS;
    }

    // Done
    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Get an ICE candidate from the description.
 */
static enum rawrtc_code get_ice_candidate_attributes(
        struct list* const candidate_lines, // not checked
        bool* const end_of_candidatesp, // de-referenced, not checked
        struct pl* const line // not checked
) {
    // ICE candidate
    if (line->l >= sdp_ice_candidate_head_length) {
        struct pl candidate_pl = {
                .p = line->p,
                .l = sdp_ice_candidate_head_length - 1,
        };
        if (pl_strcmp(&candidate_pl, sdp_ice_candidate_head) == 0) {
            struct candidate_line* candidate_line;

            // Create candidate line
            candidate_line = mem_zalloc(sizeof(*candidate_line), NULL);
            if (!candidate_line) {
                DEBUG_WARNING("Unable to create candidate line, no memory\n");
                return RAWRTC_CODE_NO_MEMORY;
            }

            // Set fields
            // Warning: The line is NOT copied - it's just a pointer to some memory provided by
            //          the caller!
            candidate_line->line = *line;

            // Add candidate line to list
            list_append(candidate_lines, &candidate_line->le, candidate_line);
        }
    }

    // End of candidates
    if (pl_strcmp(line, sdp_ice_end_of_candidates) == 0) {
        *end_of_candidatesp = true;
        return RAWRTC_CODE_SUCCESS;
    }

    // Done
    return RAWRTC_CODE_NO_VALUE;
}

/*
 * Destructor for an existing peer connection description.
 */
static void rawrtc_peer_connection_description_destroy(
        void* arg
) {
    struct rawrtc_peer_connection_description* const description = arg;

    // Un-reference
    mem_deref(description->sdp);
    mem_deref(description->sctp_capabilities);
    mem_deref(description->dtls_parameters);
    mem_deref(description->ice_parameters);
    list_flush(&description->ice_candidates);
    mem_deref(description->mid);
    mem_deref(description->remote_media_line);
    mem_deref(description->bundled_mids);
    mem_deref(description->connection);
}

/*
 * Create a description by creating an offer or answer.
 */
enum rawrtc_code rawrtc_peer_connection_description_create_internal(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        struct rawrtc_peer_connection* const connection,
        bool const offering
) {
    struct rawrtc_peer_connection_context* context;
    struct rawrtc_peer_connection_description* remote_description;
    struct rawrtc_peer_connection_description* local_description;
    enum rawrtc_code error;
    struct mbuf* sdp = NULL;
    enum rawrtc_data_transport_type data_transport_type;
    void* data_transport = NULL;

    // Check arguments
    if (!descriptionp || !connection) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get context
    context = &connection->context;

    // Ensure a data transport has been set (otherwise, there would be nothing to do)
    if (!context->data_transport) {
        DEBUG_WARNING("No data transport set\n");
        return RAWRTC_CODE_NO_VALUE;
    }

    // Ensure a remote description is available (when answering)
    remote_description = connection->remote_description;
    if (!offering && !remote_description) {
        DEBUG_WARNING("No remote description set\n");
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // TODO: Create a more sophisticated SDP mechanism based on
    //       https://github.com/nils-ohlmeier/rsdparsa

    // Allocate
    local_description = mem_zalloc(
            sizeof(*local_description), rawrtc_peer_connection_description_destroy);
    if (!local_description) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set initial values
    local_description->connection = mem_ref(connection); // Warning: Circular reference
    local_description->end_of_candidates = false;
    if (offering) {
        local_description->type = RAWRTC_SDP_TYPE_OFFER;
        local_description->trickle_ice = true;
        error = rawrtc_strdup(
                &local_description->bundled_mids, RAWRTC_PEER_CONNECTION_DESCRIPTION_MID);
        if (error) {
            goto out;
        }
        local_description->media_line_index = 0; // Since we only support one media line...
        error = rawrtc_strdup(&local_description->mid, RAWRTC_PEER_CONNECTION_DESCRIPTION_MID);
        if (error) {
            goto out;
        }
        local_description->sctp_sdp_05 = connection->configuration->sctp_sdp_05;
    } else {
        local_description->type = RAWRTC_SDP_TYPE_ANSWER;
        local_description->trickle_ice = remote_description->trickle_ice;
        local_description->bundled_mids = mem_ref(remote_description->bundled_mids);
        local_description->remote_media_line = mem_ref(remote_description->remote_media_line);
        local_description->media_line_index = remote_description->media_line_index;
        local_description->mid = mem_ref(remote_description->mid);
        local_description->sctp_sdp_05 = remote_description->sctp_sdp_05;
    }

    // Create buffer for local description
    sdp = mbuf_alloc(RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SIZE);
    if (!sdp) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }

    // Set session boilerplate
    error = set_session_boilerplate(sdp, RAWRTC_VERSION, rand_u32());
    if (error) {
        goto out;
    }

    // Set session attributes
    error = set_session_attributes(
            sdp, local_description->trickle_ice, local_description->bundled_mids);
    if (error) {
        goto out;
    }

    // Get data transport
    error = rawrtc_data_transport_get_transport(
            &data_transport_type, &data_transport, context->data_transport);
    if (error) {
        return error;
    }

    // Add data transport
    switch (data_transport_type) {
        case RAWRTC_DATA_TRANSPORT_TYPE_SCTP:
            // Add SCTP transport
            error = add_sctp_attributes(
                    sdp, data_transport, context, offering, local_description->remote_media_line,
                    local_description->mid, local_description->sctp_sdp_05);
            if (error) {
                goto out;
            }
            break;
        default:
            error = RAWRTC_CODE_UNKNOWN_ERROR;
            goto out;
            break;
    }

    // Reference SDP
    local_description->sdp = mem_ref(sdp);

    // Debug
    DEBUG_PRINTF(
            "Description (internal):\n%H\n",
            rawrtc_peer_connection_description_debug, local_description);

out:
    mem_deref(data_transport);
    mem_deref(sdp);
    if (error) {
        mem_deref(local_description);
    } else {
        // Set pointer & done
        *descriptionp = local_description;
    }
    return error;
}

/*
 * Add an ICE candidate to the description.
 */
enum rawrtc_code rawrtc_peer_connection_description_add_candidate(
        struct rawrtc_peer_connection_description* const description,
        struct rawrtc_peer_connection_ice_candidate* const candidate // nullable
) {
    enum rawrtc_code error;

    // Check arguments
    if (!description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Write candidate or end of candidates indication
    if (candidate) {
        char* candidate_sdp;

        // Already written?
        if (description->end_of_candidates) {
            return RAWRTC_CODE_INVALID_STATE;
        }

        // Get candidate SDP
        error = rawrtc_peer_connection_ice_candidate_get_sdp(&candidate_sdp, candidate);
        if (error) {
            return error;
        }

        // TODO: We would have to get the associated 'mid', media line index and username fragment
        //       as well and...
        //
        //       * inject the candidate at the correct place (compare 'mid' or line index), and
        //       * compare the username fragment against the one that's currently active (once we
        //         support ICE restarts).

        // Write candidate to SDP
        // Note: We only have one media line, so it should be fine to append this to the end
        error = rawrtc_error_to_code(mbuf_printf(
                description->sdp, "a=%s\r\n", candidate_sdp));
        if (error) {
            DEBUG_WARNING("Couldn't write candidate to description, reason: %s\n",
                          rawrtc_code_to_str(error));
            mem_deref(candidate_sdp);
            return error;
        }

        // Debug
        DEBUG_PRINTF("Added candidate line: %s\n", candidate_sdp);
        mem_deref(candidate_sdp);
    } else {
        // Already written?
        if (description->end_of_candidates) {
            DEBUG_WARNING("End of candidates has already been written\n");
            return RAWRTC_CODE_SUCCESS;
        }

        // Write end of candidates into SDP
        error = rawrtc_error_to_code(mbuf_write_str(description->sdp, "a=end-of-candidates\r\n"));
        if (error) {
            return error;
        }
        description->end_of_candidates = true;

        // Debug
        DEBUG_PRINTF(
                "Description (end-of-candidates):\n%H\n",
                rawrtc_peer_connection_description_debug, description);
    }

    // Done
    return RAWRTC_CODE_SUCCESS;
}

// Helper for parsing SDP attributes
#define HANDLE_ATTRIBUTE(code)\
error = code;\
if (error == RAWRTC_CODE_SUCCESS) {\
    break;\
} else if (error != RAWRTC_CODE_NO_VALUE) {\
    goto out;\
    break;\
}\

/*
 * Print debug information for a peer connection description.
 */
int rawrtc_peer_connection_description_debug(
        struct re_printf* const pf,
        struct rawrtc_peer_connection_description* const description
) {
    int err = 0;
    struct le* le;

    // Check arguments
    if (!description) {
        return 0;
    }

    err |= re_hprintf(pf, "----- Peer Connection Description <%p>\n", description);

    // Print general fields
    err |= re_hprintf(pf, "  peer_connection=");
    if (description->connection) {
        err |= re_hprintf(pf, "%p\n", description->connection);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  sdp_type=%s\n", rawrtc_sdp_type_to_str(description->type));
    err |= re_hprintf(pf, "  trickle_ice=%s\n", description->trickle_ice ? "yes" : "no");
    err |= re_hprintf(pf, "  bundled_mids=");
    if (description->bundled_mids) {
        err |= re_hprintf(pf, "\"%s\"\n", description->bundled_mids);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  remote_media_line=");
    if (description->remote_media_line) {
        err |= re_hprintf(pf, "\"%s\"\n", description->remote_media_line);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  media_line_index=%"PRIu8"\n", description->media_line_index);
    err |= re_hprintf(pf, "  mid=");
    if (description->mid) {
        err |= re_hprintf(pf, "\"%s\"\n", description->mid);
    } else {
        err |= re_hprintf(pf, "n/a\n");
    }
    err |= re_hprintf(pf, "  sctp_sdp_05=%s\n", description->sctp_sdp_05 ? "yes" : "no");
    err |= re_hprintf(
            pf, "  end_of_candidates=%s\n", description->end_of_candidates ? "yes" : "no");

    // Print ICE parameters
    if (description->ice_parameters) {
        err |= re_hprintf(pf, "%H", rawrtc_ice_parameters_debug, description->ice_parameters);
    } else {
        err |= re_hprintf(pf, "  ICE Parameters <n/a>\n");
    }

    // Print ICE candidates
    le = list_head(&description->ice_candidates);
    if (le) {
        for (; le != NULL; le = le->next) {
            struct rawrtc_peer_connection_ice_candidate *const candidate = le->data;
            err |= re_hprintf(pf, "%H", rawrtc_peer_connection_ice_candidate_debug, candidate);
        }
    } else {
        err |= re_hprintf(pf, "  ICE Candidates <n/a>\n");
    }

    // Print DTLS parameters
    if (description->dtls_parameters) {
        err |= re_hprintf(pf, "%H", rawrtc_dtls_parameters_debug, description->dtls_parameters);
    } else {
        err |= re_hprintf(pf, "  DTLS Parameters <n/a>\n");
    }

    // Print SCTP capabilities & port
    if (description->sctp_capabilities) {
        err |= re_hprintf(pf, "%H", rawrtc_sctp_capabilities_debug, description->sctp_capabilities);
    } else {
        err |= re_hprintf(pf, "  SCTP Capabilities <n/a>\n");
    }
    err |= re_hprintf(
            pf, "  sctp_port=%"PRIu16"\n", description->sctp_port);

    // Print SDP
    err |= re_hprintf(pf, "  sdp=\n%b", description->sdp->buf, description->sdp->end);

    // Done
    return err;
}

/*
 * Create a description by parsing it from SDP.
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_create(
        struct rawrtc_peer_connection_description** const descriptionp, // de-referenced
        enum rawrtc_sdp_type const type,
        char const* const sdp
) {
    enum rawrtc_code error;
    struct rawrtc_peer_connection_description* remote_description;
    char const* cursor;
    bool media_line = false;
    struct le* le;

    // ICE parameters
    char* ice_username_fragment = NULL;
    char* ice_password = NULL;
    bool ice_lite = false;

    // DTLS parameters
    enum rawrtc_dtls_role dtls_role = RAWRTC_DTLS_ROLE_AUTO;
    struct list dtls_fingerprints = LIST_INIT;

    // SCTP capabilities
    uint64_t sctp_max_message_size = RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_MAX_MESSAGE_SIZE;

    // ICE candidate lines (temporarily stored, so it can be parsed later)
    struct list ice_candidate_lines = LIST_INIT;

    // Check arguments
    if (!descriptionp || !sdp) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // We only accept 'offer' or 'answer' at the moment
    // TODO: Handle the other ones as well
    if (type != RAWRTC_SDP_TYPE_OFFER && type != RAWRTC_SDP_TYPE_ANSWER) {
        DEBUG_WARNING("Only 'offer' or 'answer' descriptions can be handled at the moment\n");
        return RAWRTC_CODE_NOT_IMPLEMENTED;
    }

    // Allocate
    remote_description = mem_zalloc(
            sizeof(*remote_description), rawrtc_peer_connection_description_destroy);
    if (!remote_description) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Set fields to initial values
    remote_description->type = type;
    remote_description->trickle_ice = false;
    remote_description->media_line_index = 0; // Since we only support one media line...
    remote_description->sctp_sdp_05 = true;
    list_init(&remote_description->ice_candidates);
    remote_description->sctp_port = RAWRTC_PEER_CONNECTION_DESCRIPTION_DEFAULT_SCTP_PORT;

    // Find required session and media attributes
    cursor = sdp;
    while (*cursor != '\0') {
        struct pl line;
        char sdp_type;

        // Ignore lines beginning with '\r' or '\n'
        if (*cursor == '\r' || *cursor == '\n') {
            ++cursor;
            continue;
        }

        // Find next line or end of string
        for (line.p = cursor, line.l = 0;
             *cursor != '\r' && *cursor != '\n' && *cursor != '\0';
             ++cursor, ++line.l) {}

        // Get line type and move line cursor to value
        if (line.l < 2) {
            DEBUG_WARNING("Invalid SDP line: %r\n", &line);
            break;
        }
        sdp_type = *line.p;
        pl_advance(&line, 2);

        // Are we interested in this line?
        switch (sdp_type) {
            case 'a': {
                // Be aware we're using a macro here which does the following:
                //
                // * if the function returns 'success', break (and therefore don't continue
                //   parsing other attributes on this line).
                // * if the function returns 'no value', do nothing (and therefore continue parsing
                //   other attributes on this line).
                // * if the function returns anything else (which indicates an error), set 'error'
                //   and jump to 'out'.
                HANDLE_ATTRIBUTE(get_general_attributes(
                        &remote_description->bundled_mids, &remote_description->mid, &line));
                HANDLE_ATTRIBUTE(get_ice_attributes(
                        &remote_description->trickle_ice, &ice_username_fragment, &ice_password,
                        &ice_lite, &line));
                HANDLE_ATTRIBUTE(get_dtls_attributes(&dtls_role, &dtls_fingerprints, &line));
                HANDLE_ATTRIBUTE(get_sctp_attributes(
                        &remote_description->sctp_port, &sctp_max_message_size, &line));
                HANDLE_ATTRIBUTE(get_ice_candidate_attributes(
                        &ice_candidate_lines, &remote_description->end_of_candidates,
                        &line));
                break;
            }
            case 'm': {
                struct pl application;
                size_t i;

                // Ensure amount of media lines is exactly one
                if (media_line) {
                    DEBUG_WARNING("Unable to handle more than one media line\n");
                    error = RAWRTC_CODE_NOT_IMPLEMENTED;
                    goto out;
                }

                // Parse media line
                if (re_regex(line.p, line.l, sdp_application_dtls_sctp_regex, NULL, &application)) {
                    DEBUG_WARNING("Unsupport media line: %r\n", &line);
                    error = RAWRTC_CODE_NOT_IMPLEMENTED;
                    goto out;
                }

                // Check if the application matches some kind of DTLS/SCTP variant (ugh...)
                for (i = 0; i < sdp_application_dtls_sctp_variants_length; ++i) {
                    if (pl_strcmp(&application, sdp_application_dtls_sctp_variants[i]) == 0) {
                        media_line = true;
                    }
                }
                if (!media_line) {
                    DEBUG_WARNING("Unsupported application on media line: %r\n", &application);
                    error = RAWRTC_CODE_NOT_IMPLEMENTED;
                    goto out;
                }

                // Copy media line
                error = rawrtc_sdprintf(&remote_description->remote_media_line, "%r", &line);
                if (error) {
                    goto out;
                }

                // Done
                break;
            }
            default:
                DEBUG_PRINTF("Ignoring %s line: %c=%r\n",
                             media_line ? "media" : "session", sdp_type, &line);
                break;
        }
    }

    // Return 'no value' in case there was no media line
    if (!media_line) {
        error = RAWRTC_CODE_NO_VALUE;
        goto out;
    }

    // Create ICE parameters (if possible)
    if (ice_username_fragment && ice_password) {
        error = rawrtc_ice_parameters_create(
                &remote_description->ice_parameters, ice_username_fragment, ice_password, ice_lite);
        if (error) {
            goto out;
        }
    }

    // Create DTLS parameters (if possible)
    if (!list_isempty(&dtls_fingerprints)) {
        error = rawrtc_dtls_parameters_create_internal(
                &remote_description->dtls_parameters, dtls_role, &dtls_fingerprints);
        if (error) {
            goto out;
        }
    }

    // Create SCTP capabilities
    error = rawrtc_sctp_capabilities_create(
            &remote_description->sctp_capabilities, sctp_max_message_size);
    if (error) {
        goto out;
    }

    // Late parsing of ICE candidates.
    // Note: This is required since the 'mid' and the username fragment may be parsed after a
    //       candidate has been found.
    for (le = list_head(&ice_candidate_lines); le != NULL; le = le->next) {
        struct candidate_line* const candidate_line = le->data;

        // Create ICE candidate
        struct rawrtc_peer_connection_ice_candidate* candidate;
        error = rawrtc_peer_connection_ice_candidate_create_internal(
                &candidate, &candidate_line->line, remote_description->mid,
                &remote_description->media_line_index, ice_username_fragment);
        if (error) {
            goto out;
        }

        // Add ICE candidate to the list
        DEBUG_PRINTF("Adding ICE candidate to description\n");
        list_append(&remote_description->ice_candidates, &candidate->le, candidate);
    }

    // Copy SDP
    remote_description->sdp = mbuf_alloc(strlen(sdp));
    if (!remote_description->sdp) {
        error = RAWRTC_CODE_NO_MEMORY;
        goto out;
    }
    mbuf_write_str(remote_description->sdp, sdp);

    // Debug
    DEBUG_PRINTF(
            "Description (parsed):\n%H\n",
            rawrtc_peer_connection_description_debug, remote_description);

    // Done
    error = RAWRTC_CODE_SUCCESS;

out:
    // Un-reference
    list_flush(&ice_candidate_lines);
    list_flush(&dtls_fingerprints);
    mem_deref(ice_password);
    mem_deref(ice_username_fragment);
    if (error) {
        mem_deref(remote_description);
    } else {
        // Set pointer & done
        *descriptionp = remote_description;
    }
    return error;
}

/*
 * Get the SDP type of the description.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp_type(
        enum rawrtc_sdp_type* const typep, // de-referenced
        struct rawrtc_peer_connection_description* const description
) {
    // Check arguments
    if (!typep || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Set SDP type
    *typep = description->type;

    // Done
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Get the SDP of the description.
 * `*sdpp` will be set to a copy of the SDP that must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp(
        char** const sdpp, // de-referenced
        struct rawrtc_peer_connection_description* const description
) {
    // Check arguments
    if (!sdpp || !description) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Copy SDP
    return rawrtc_sdprintf(sdpp, "%b", description->sdp->buf, description->sdp->end);
}

static enum rawrtc_sdp_type const map_enum_sdp_type[] = {
    RAWRTC_SDP_TYPE_OFFER,
    RAWRTC_SDP_TYPE_PROVISIONAL_ANSWER,
    RAWRTC_SDP_TYPE_ANSWER,
    RAWRTC_SDP_TYPE_ROLLBACK,
};

static char const * const map_str_sdp_type[] = {
    "offer",
    "pranswer",
    "answer",
    "rollback",
};

static size_t const map_sdp_type_length =
        ARRAY_SIZE(map_enum_sdp_type);

/*
 * Translate an SDP type to str.
 */
char const * rawrtc_sdp_type_to_str(
        enum rawrtc_sdp_type const type
) {
    size_t i;

    for (i = 0; i < map_sdp_type_length; ++i) {
        if (map_enum_sdp_type[i] == type) {
            return map_str_sdp_type[i];
        }
    }

    return "???";
}

/*
 * Translate a str to an SDP type.
 */
enum rawrtc_code rawrtc_str_to_sdp_type(
        enum rawrtc_sdp_type* const typep, // de-referenced
        char const* const str
) {
    size_t i;

    // Check arguments
    if (!typep || !str) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    for (i = 0; i < map_sdp_type_length; ++i) {
        if (str_casecmp(map_str_sdp_type[i], str) == 0) {
            *typep = map_enum_sdp_type[i];
            return RAWRTC_CODE_SUCCESS;
        }
    }

    return RAWRTC_CODE_NO_VALUE;
}
