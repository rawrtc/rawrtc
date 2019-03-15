#pragma once
#include <rawrtcc/code.h>
#include <re.h>

/*
 * SDP type.
 */
enum rawrtc_sdp_type {
    RAWRTC_SDP_TYPE_OFFER,
    RAWRTC_SDP_TYPE_PROVISIONAL_ANSWER,
    RAWRTC_SDP_TYPE_ANSWER,
    RAWRTC_SDP_TYPE_ROLLBACK,
};

/*
 * Peer connection description.
 */
struct rawrtc_peer_connection_description;

/*
 * Create a description by parsing it from SDP.
 * `*descriptionp` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_create(
    struct rawrtc_peer_connection_description** const descriptionp,  // de-referenced
    enum rawrtc_sdp_type const type,
    char const* const sdp);

/*
 * Get the SDP type of the description.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp_type(
    enum rawrtc_sdp_type* const typep,  // de-referenced
    struct rawrtc_peer_connection_description* const description);

/*
 * Get the SDP of the description.
 * `*sdpp` will be set to a copy of the SDP that must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_description_get_sdp(
    char** const sdpp,  // de-referenced
    struct rawrtc_peer_connection_description* const description);

/*
 * Translate an SDP type to str.
 */
char const* rawrtc_sdp_type_to_str(enum rawrtc_sdp_type const type);

/*
 * Translate a str to an SDP type.
 */
enum rawrtc_code rawrtc_str_to_sdp_type(
    enum rawrtc_sdp_type* const typep,  // de-referenced
    char const* const str);
