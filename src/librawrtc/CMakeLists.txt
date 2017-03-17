# Library sources
set(rawrtc_SOURCES
        candidate_helper.c
        certificate.c
        crc32c.c
        data_channel.c
        data_channel_options.c
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
        sctp_redirect_transport.c
        sctp_capabilities.c
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

# Generate pkg-config file & install it
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmakein
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
        DESTINATION lib/pkgconfig)
