# Library sources
set(anyrtc_SOURCES
        ice_candidate.c
        ice_gatherer.c
        ice_transport.c
        main.c
        utils.c)

# Setup library (link & install)
add_library(anyrtc SHARED ${anyrtc_SOURCES})
target_link_libraries(anyrtc
        ${anyrtc_DEP_LIBRARIES})
add_library(anyrtc-static STATIC ${anyrtc_SOURCES})
target_link_libraries(anyrtc-static
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS anyrtc anyrtc-static
        DESTINATION lib)
