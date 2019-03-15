#pragma once
#include "common.h"
#include <rawrtc.h>
#include <rawrtcc.h>
#include <rawrtcdc.h>
#include <re.h>

/*
 * Set ICE parameters in dictionary.
 */
void set_ice_parameters(struct rawrtc_ice_parameters* const parameters, struct odict* const dict);

/*
 * Set ICE candidates in dictionary.
 */
void set_ice_candidates(struct rawrtc_ice_candidates* const parameters, struct odict* const array);

/*
 * Set DTLS parameters in dictionary.
 */
void set_dtls_parameters(struct rawrtc_dtls_parameters* const parameters, struct odict* const dict);

/*
 * Set SCTP parameters in dictionary.
 */
void set_sctp_parameters(
    struct rawrtc_sctp_transport* const transport,
    struct sctp_parameters* const parameters,
    struct odict* const dict);

#if RAWRTC_HAVE_SCTP_REDIRECT_TRANSPORT
/*
 * Set SCTP redirect parameters in dictionary.
 */
void set_sctp_redirect_parameters(
    struct rawrtc_sctp_redirect_transport* const transport,
    struct sctp_parameters* const parameters,
    struct odict* const dict);
#endif

/*
 * Get ICE parameters from dictionary.
 */
enum rawrtc_code get_ice_parameters(
    struct rawrtc_ice_parameters** const parametersp, struct odict* const dict);

/*
 * Get ICE candidates from dictionary.
 * Filter by enabled ICE candidate types if `client` argument is set to
 * non-NULL.
 */
enum rawrtc_code get_ice_candidates(
    struct rawrtc_ice_candidates** const candidatesp,
    struct odict* const dict,
    struct client* const client);

/*
 * Get DTLS parameters from dictionary.
 */
enum rawrtc_code get_dtls_parameters(
    struct rawrtc_dtls_parameters** const parametersp, struct odict* const dict);

/*
 * Get SCTP parameters from dictionary.
 */
enum rawrtc_code get_sctp_parameters(
    struct sctp_parameters* const parameters, struct odict* const dict);
