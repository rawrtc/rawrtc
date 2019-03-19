#pragma once
#include <rawrtcc/code.h>

/*
 * Transport layers.
 */
enum {
    RAWRTC_LAYER_SCTP = 20,
    RAWRTC_LAYER_DTLS_SRTP_STUN = 10,  // TODO: Pretty sure we are able to detect STUN earlier
    RAWRTC_LAYER_ICE = 0,
    RAWRTC_LAYER_STUN = -10,
    RAWRTC_LAYER_TURN = -10,
};

/*
 * Configuration.
 */
struct rawrtc_config;

/*
 * Initialise rawrtc. Must be called before making a call to any other
 * function.
 *
 * Note: In case `init_re` is not set to `true`, you MUST initialise
 *       re yourselves before calling this function.
 */
enum rawrtc_code rawrtc_init(bool const init_re);

/*
 * Close rawrtc and free up all resources.
 *
 * Note: In case `close_re` is not set to `true`, you MUST close
 *       re yourselves.
 */
enum rawrtc_code rawrtc_close(bool const close_re);
