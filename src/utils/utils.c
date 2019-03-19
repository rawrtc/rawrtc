#include "utils.h"
#include <rawrtc/utils.h>
#include <rawrtcc/code.h>
#include <re.h>
#include <stdarg.h>  // va_*
#include <stdio.h>  // sprintf
#include <string.h>  // strlen

/*
 * Convert binary to hex string where each value is separated by a
 * colon.
 */
enum rawrtc_code rawrtc_bin_to_colon_hex(
    char** const destinationp,  // de-referenced
    uint8_t* const source,
    size_t const length) {
    char* hex_str;
    char* hex_ptr;
    size_t i;
    int ret;
    enum rawrtc_code error = RAWRTC_CODE_SUCCESS;

    // Check arguments
    if (!destinationp || !source) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Allocate hex string
    hex_str = mem_zalloc(length > 0 ? (length * 3) : 1, NULL);
    if (!hex_str) {
        return RAWRTC_CODE_NO_MEMORY;
    }

    // Bin to hex
    hex_ptr = hex_str;
    for (i = 0; i < length; ++i) {
        if (i > 0) {
            *hex_ptr = ':';
            ++hex_ptr;
        }
        ret = sprintf(hex_ptr, "%02X", source[i]);
        if (ret != 2) {
            error = RAWRTC_CODE_UNKNOWN_ERROR;
            goto out;
        } else {
            hex_ptr += ret;
        }
    }

out:
    if (error) {
        mem_deref(hex_str);
    } else {
        // Set pointer
        *destinationp = hex_str;
    }
    return error;
}

/*
 * Convert hex string with colon-separated hex values to binary.
 */
enum rawrtc_code rawrtc_colon_hex_to_bin(
    size_t* const bytes_written,  // de-referenced
    uint8_t* const buffer,  // written into
    size_t const buffer_size,
    char* source) {
    size_t hex_length;
    size_t bin_length;
    size_t i;

    // Check arguments
    if (!bytes_written || !buffer || !source) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Validate length
    hex_length = strlen(source);
    if (hex_length > 0 && hex_length % 3 != 2) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Determine size
    bin_length = hex_length > 0 ? (size_t)((hex_length + 1) / 3) : 0;
    if (bin_length > buffer_size) {
        return RAWRTC_CODE_INSUFFICIENT_SPACE;
    }

    // Hex to bin
    for (i = 0; i < bin_length; ++i) {
        if (i > 0) {
            // Skip colon
            ++source;
        }
        buffer[i] = ch_hex(*source) << 4;
        ++source;
        buffer[i] += ch_hex(*source);
        ++source;
    }

    // Done
    *bytes_written = bin_length;
    return RAWRTC_CODE_SUCCESS;
}

/*
 * Destructor for an existing array container that did reference each
 * item.
 */
static void rawrtc_array_container_destroy(void* arg) {
    struct rawrtc_array_container* const container = arg;
    size_t i;

    // Un-reference each item
    for (i = 0; i < container->n_items; ++i) {
        mem_deref(container->items[i]);
    }
}

/*
 * Convert a list to a dynamically allocated array container.
 *
 * If `reference` is set to `true`, each item in the list will be
 * referenced and a destructor will be added that unreferences each
 * item when unreferencing the array.
 */
enum rawrtc_code rawrtc_list_to_array(
    struct rawrtc_array_container** containerp,  // de-referenced
    struct list const* const list,
    bool reference) {
    size_t n;
    struct rawrtc_array_container* container;
    struct le* le;
    size_t i;

    // Check arguments
    if (!containerp || !list) {
        return RAWRTC_CODE_INVALID_ARGUMENT;
    }

    // Get list length
    n = list_count(list);

    // Allocate array & set length immediately
    container = mem_zalloc(
        sizeof(*container) + sizeof(void*) * n, reference ? rawrtc_array_container_destroy : NULL);
    if (!container) {
        return RAWRTC_CODE_NO_MEMORY;
    }
    container->n_items = n;

    // Copy pointer to each item
    for (le = list_head(list), i = 0; le != NULL; le = le->next, ++i) {
        if (reference) {
            mem_ref(le->data);
        }
        container->items[i] = le->data;
    }

    // Set pointer & done
    *containerp = container;
    return RAWRTC_CODE_SUCCESS;
}
