# Library sources
set(anyrtc_SOURCES
        ice_gatherer.c)

# Setup library (link & install)
add_library(anyrtc SHARED ${anyrtc_SOURCES})
add_library(anyrtc-static STATIC ${anyrtc_SOURCES})
target_link_libraries(anyrtc anyrtc-static
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS anyrtc anyrtc-static
        DESTINATION lib)
