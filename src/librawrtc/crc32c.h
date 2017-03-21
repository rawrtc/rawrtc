#pragma once
#include <re/re_types.h>
#include <stdlib.h>

/*
 * Compute a CRC-32C.  If the crc32 instruction is available, use the hardware
 * version.  Otherwise, use the software version.
 */
uint32_t crc32c(
    uint32_t crc,
    void const* buf,
    size_t len
);
