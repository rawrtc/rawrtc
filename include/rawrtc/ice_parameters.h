#pragma once
#include <rawrtcc/code.h>
#include <re.h>

/*
 * ICE parameters.
 */
struct rawrtc_ice_parameters;

/*
 * Create a new ICE parameters instance.
 * `*parametersp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_create(
    struct rawrtc_ice_parameters** const parametersp,  // de-referenced
    char* const username_fragment,  // copied
    char* const password,  // copied
    bool const ice_lite);

/*
 * Get the ICE parameter's username fragment value.
 * `*username_fragmentp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_username_fragment(
    char** const username_fragmentp,  // de-referenced
    struct rawrtc_ice_parameters* const parameters);

/*
 * Get the ICE parameter's password value.
 * `*passwordp` must be unreferenced.
 */
enum rawrtc_code rawrtc_ice_parameters_get_password(
    char** const passwordp,  // de-referenced
    struct rawrtc_ice_parameters* const parameters);

/*
 * Get the ICE parameter's ICE lite value.
 */
enum rawrtc_code rawrtc_ice_parameters_get_ice_lite(
    bool* const ice_litep,  // de-referenced
    struct rawrtc_ice_parameters* const parameters);
