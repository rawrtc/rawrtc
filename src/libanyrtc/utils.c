#include <stdarg.h>
#include <anyrtc.h>
#include "utils.h"

struct re_printf anyrtc_stdout = {anyrtc_stdout_handler, NULL};

/*
 * TODO: Add codes from trice_lcand_add
 */
enum anyrtc_code anyrtc_code_re_translate(
        int code
) {
    switch (code) {
        case 0:
            return ANYRTC_CODE_SUCCESS;
        case EINVAL:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        case ENOMEM:
            return ANYRTC_CODE_NO_MEMORY;
        default:
            return ANYRTC_CODE_UNKNOWN_ERROR;
    }
}

int anyrtc_stdout_handler(
        char const* const str,
        size_t const size,
        void* const arg
) {
    (void) arg;

    if (fwrite(str, size, 1, stdout) != 1) {
        return ENOMEM;
    }

    return 0;
}

enum anyrtc_code anyrtc_strdup(
        char** const destination,
        char const * const source
) {
    int err = str_dup(destination, source);
    return anyrtc_code_re_translate(err);
}

enum anyrtc_code anyrtc_snprintf(
        char* const destination,
        size_t const size,
        char* const formatter,
        ...
) {
    va_list args;
    va_start(args, formatter);
    int err = re_vsnprintf(destination, size, formatter, args);
    va_end(args);

    // For some reason, re_vsnprintf does return -1 on argument error
    switch (err) {
        case -1:
            return ANYRTC_CODE_INVALID_ARGUMENT;
        default:
            return anyrtc_code_re_translate(err);
    }
}

