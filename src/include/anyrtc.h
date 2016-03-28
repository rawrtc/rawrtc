#pragma once
// TODO: Move this section into meson build
#define ANYRTC_DEBUG 1

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define ZF_LOG_LIBRARY_PREFIX anyrtc_
#ifdef ANYRTC_DEBUG
    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_DEBUG
#else
    #define ANYRTC_ZF_LOG_LEVEL ZF_LOG_WARN
#endif
#include <zf_log.h>

// TODO: Import from previously drafted ortcdc interface
