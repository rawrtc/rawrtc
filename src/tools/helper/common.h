#pragma once
#include <rawrtc.h>

enum {
    PARAMETERS_MAX_LENGTH = 8192,
};

/*
 * SCTP parameters that need to be negotiated.
 */
struct sctp_parameters {
    struct rawrtc_sctp_capabilities* capabilities;
    uint16_t port;
};

/*
 * Client structure. Can be extended.
 */
struct client {
    char* name;
};

/*
 * Data channel helper structure. Can be extended.
 */
struct data_channel {
    struct rawrtc_data_channel* channel;
    char* label;
    struct client* client;
};

/*
 * Ignore success code list.
 */
extern enum rawrtc_code const ignore_success[];
extern size_t const ignore_success_length;

/*
 * Helper macros for exiting with error messages.
 */
#define EOE(code) exit_on_error(code, ignore_success,\
    sizeof(enum rawrtc_code) / sizeof(enum rawrtc_code), __FILE__, __LINE__)
#define EOEIGN(code, ignore) exit_on_error(code, ignore,\
    ignore_success_length, __FILE__, __LINE__)
#define EOR(code) exit_on_posix_error(code, __FILE__, __LINE__)
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || (__GNUC__ >= 3)
#define EWE(...) exit_with_error(__FILE__, __LINE__, __VA_ARGS__)
#elif defined(__GNUC__)
#define EWE(args...) exit_with_error(__FILE__, __LINE__, args)
#endif
