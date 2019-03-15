#pragma once
#include <rawrtcc/code.h>
#include <re.h>

// Dependencies
struct rawrtc_ice_candidate;

/*
 * Peer connection ICE candidate.
 */
struct rawrtc_peer_connection_ice_candidate;

/*
 * Create a new ICE candidate from SDP.
 * `*candidatesp` must be unreferenced.
 *
 * Note: This is equivalent to creating an `RTCIceCandidate` from an
 *       `RTCIceCandidateInit` instance in the W3C WebRTC
 *       specification.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_create(
    struct rawrtc_peer_connection_ice_candidate** const candidatep,  // de-referenced
    char* const sdp,
    char* const mid,  // nullable, copied
    uint8_t const* const media_line_index,  // nullable, copied
    char* const username_fragment  // nullable, copied
);

/*
 * Encode the ICE candidate into SDP.
 * `*sdpp` will be set to a copy of the SDP attribute that must be
 * unreferenced.
 *
 * Note: This is equivalent to the `candidate` attribute of the W3C
 *       WebRTC specification's `RTCIceCandidateInit`.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp(
    char** const sdpp,  // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate);

/*
 * Get the media stream identification tag the ICE candidate is
 * associated to.
 * `*midp` will be set to a copy of the candidate's mid and must be
 * unreferenced.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no 'mid' has been set.
 * Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and `*midp* must
 * be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp_mid(
    char** const midp,  // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate);

/*
 * Get the media stream line index the ICE candidate is associated to.
 * Return `RAWRTC_CODE_NO_VALUE` in case no media line index has been
 * set.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_sdp_media_line_index(
    uint8_t* const media_line_index,  // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate);

/*
 * Get the username fragment the ICE candidate is associated to.
 * `*username_fragmentp` will be set to a copy of the candidate's
 * username fragment and must be unreferenced.
 *
 * Return `RAWRTC_CODE_NO_VALUE` in case no username fragment has been
 * set. Otherwise, `RAWRTC_CODE_SUCCESS` will be returned and
 * `*username_fragmentp* must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_username_fragment(
    char** const username_fragmentp,  // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate);

/*
 * Get the underlying ORTC ICE candidate from the ICE candidate.
 * `*ortc_candidatep` must be unreferenced.
 */
enum rawrtc_code rawrtc_peer_connection_ice_candidate_get_ortc_candidate(
    struct rawrtc_ice_candidate** const ortc_candidatep,  // de-referenced
    struct rawrtc_peer_connection_ice_candidate* const candidate);
