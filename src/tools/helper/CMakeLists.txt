# Helper sources
set(rawrtc_HELPER
        common.c
        handler.c
        parameters.c
        utils.c)

# Setup helper library for linker
add_library(rawrtc-helper STATIC ${rawrtc_HELPER})
target_link_libraries(rawrtc-helper
        rawrtc)
if (SCTP_REDIRECT_TRANSPORT)
  target_compile_definitions(rawrtc-helper PRIVATE SCTP_REDIRECT_TRANSPORT)
endif()
