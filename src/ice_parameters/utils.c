#include "parameters.h"
#include <re.h>

/*
 * Print debug information for ICE parameters.
 */
int rawrtc_ice_parameters_debug(
    struct re_printf* const pf, struct rawrtc_ice_parameters const* const parameters) {
    int err = 0;

    // Check arguments
    if (!parameters) {
        return 0;
    }

    err |= re_hprintf(pf, "  ICE Parameters <%p>:\n", parameters);

    // Username fragment
    err |= re_hprintf(pf, "    username_fragment=\"%s\"\n", parameters->username_fragment);

    // Password
    err |= re_hprintf(pf, "    password=\"%s\"\n", parameters->password);

    // ICE lite
    err |= re_hprintf(pf, "    ice_lite=%s\n", parameters->ice_lite ? "yes" : "no");

    // Done
    return err;
}
