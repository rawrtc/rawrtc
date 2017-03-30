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
    char** ice_candidate_types;
    size_t n_ice_candidate_types;
};

/*
 * Data channel helper structure. Can be extended.
 */
struct data_channel_helper {
    struct le le;
    struct rawrtc_data_channel* channel;
    char* label;
    struct client* client;
    void* arg;
};

/*
 * Ignore success code list.
 */
extern enum rawrtc_code const ignore_success[];
extern size_t const ignore_success_length;

/*
 * Helper macros for exiting with error messages.
 */
#define EOE(code) exit_on_error(code, ignore_success, ignore_success_length, __FILE__, __LINE__)
#define EOEIGN(code, ignore) exit_on_error(code, ignore, ARRAY_SIZE(ignore), __FILE__, __LINE__)
#define EOR(code) exit_on_posix_error(code, __FILE__, __LINE__)
#define EOP(code) exit_on_posix_error((code == -1) ? errno : 0, __FILE__, __LINE__)
#if (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || (__GNUC__ >= 3)
#define EWE(...) exit_with_error(__FILE__, __LINE__, __VA_ARGS__)
#elif defined(__GNUC__)
#define EWE(args...) exit_with_error(__FILE__, __LINE__, args)
#endif

/*
 * Function to be called before exiting.
 */
void before_exit();

/*
 * Exit on error code.
 */
void exit_on_error(
    enum rawrtc_code const code,
    enum rawrtc_code const ignore[],
    size_t const n_ignore,
    char const* const file,
    uint32_t const line
);

/*
* Exit on POSIX error code.
*/
void exit_on_posix_error(
    int code,
    char const* const file,
    uint32_t line
);

/*
* Exit with a custom error message.
*/
void exit_with_error(
    char const* const file,
    uint32_t line,
    char const* const formatter,
    ...
);

/*
* Check if the ICE candidate type is enabled.
*/
bool ice_candidate_type_enabled(
    struct client* const client,
    enum rawrtc_ice_candidate_type const type
);

/*
 * Print ICE candidate information.
 */
void print_ice_candidate(
    struct rawrtc_ice_candidate* const candidate,
    char const * const url, // read-only
    struct client* const client
);
