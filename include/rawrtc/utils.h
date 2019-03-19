#pragma once
#include <re.h>

/*
 * Array container.
 */
struct rawrtc_array_container {
    size_t n_items;
    void* items[];
};
