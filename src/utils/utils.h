#pragma once
#include <rawrtc/utils.h>
#include <rawrtcc/code.h>
#include <re.h>

enum rawrtc_code rawrtc_bin_to_colon_hex(
    char** const destinationp,  // de-referenced
    uint8_t* const source,
    size_t const length);

enum rawrtc_code rawrtc_colon_hex_to_bin(
    size_t* const bytes_written,  // de-referenced
    uint8_t* const buffer,  // written into
    size_t const buffer_size,
    char* source);

enum rawrtc_code rawrtc_list_to_array(
    struct rawrtc_array_container** containerp,  // de-referenced
    struct list const* const list,
    bool reference);
