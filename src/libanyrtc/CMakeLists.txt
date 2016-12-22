# Library sources
set(anyrtc_SOURCES
        candidate_helper.c
        certificate.c
        crc32c.c
        data_channel.c
        data_channel_parameters.c
        data_transport.c
        dtls_parameters.c
        dtls_transport.c
        ice_candidate.c
        ice_gatherer.c
        ice_parameters.c
        ice_transport.c
        main.c
        message_buffer.c
        redirect_transport.c
        sctp_transport.c
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
