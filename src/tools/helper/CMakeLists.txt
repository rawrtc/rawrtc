# Helper sources
set(rawrtc_HELPER
        common.c
        handler.c
        parameters.c
        utils.c)

# Setup helper library for linker
add_library(rawrtc-helper SHARED ${rawrtc_HELPER})
target_link_libraries(rawrtc-helper
        rawrtc)
