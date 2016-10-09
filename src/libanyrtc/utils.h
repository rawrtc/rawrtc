#pragma once
#include <anyrtc.h>

enum anyrtc_code anyrtc_code_re_translate(
    int code
);

int anyrtc_stdout_handler(
    char const* const str,
    size_t const size,
    void* const arg
);

enum anyrtc_code anyrtc_strdup(
    char** const destination,
    char const * const source
);

enum anyrtc_code anyrtc_snprintf(
    char* const destination,
    size_t const size,
    char* const formatter,
    ...
);

extern struct re_printf anyrtc_stdout;
