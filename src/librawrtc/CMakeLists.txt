# Library sources
set(rawrtc_SOURCES
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
add_library(rawrtc SHARED ${rawrtc_SOURCES})
target_link_libraries(rawrtc
        ${rawrtc_DEP_LIBRARIES})
add_library(rawrtc-static STATIC ${rawrtc_SOURCES})
target_link_libraries(rawrtc-static
        ${rawrtc_DEP_LIBRARIES})
install(TARGETS rawrtc rawrtc-static
        DESTINATION lib)
