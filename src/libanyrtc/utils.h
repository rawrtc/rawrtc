#pragma once
#include <anyrtc.h>

enum anyrtc_code anyrtc_code_re_translate(
    int code
);

enum anyrtc_code anyrtc_strdup(
    char** const destination,
    char const * const source
);

enum anyrtc_code anyrtc_snprintf(
    char* const destination,
    size_t size const,
    char* const formatter,
    ...
);
