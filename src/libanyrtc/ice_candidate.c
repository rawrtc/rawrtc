#include <anyrtc.h>
#include "ice_candidate.h"
#include "utils.h"

#define DEBUG_MODULE "ice-candidate"
#define DEBUG_LEVEL 7
#include <re_dbg.h>

/*
 * Calculate the ICE candidate priority.
 * TODO: https://tools.ietf.org/html/draft-ietf-ice-rfc5245bis-04#section-4.1.2.1
 */
uint32_t anyrtc_ice_candidate_calculate_priority(
        enum ice_cand_type const candidate_type,
        int const protocol,
        enum ice_tcptype const tcp_type
) {
    return 0;
}
