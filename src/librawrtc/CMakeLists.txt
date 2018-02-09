# Library sources
set(rawrtc_SOURCES
        candidate_helper.c
        certificate.c
        data_channel.c
        data_channel_options.c
        data_channel_parameters.c
        data_transport.c
        dtls_parameters.c
        dtls_transport.c
        ice_candidate.c
        ice_gatherer.c
        ice_gather_options.c
        ice_parameters.c
        ice_server.c
        ice_transport.c
        main.c
        message_buffer.c
        peer_connection.c
        peer_connection_configuration.c
        peer_connection_description.c
        peer_connection_ice_candidate.c
        sctp_capabilities.c
        sctp_transport.c
        utils.c)

# If we are building the SCTP redirect transport tool
if (SCTP_REDIRECT_TRANSPORT)
    # Add the relevant source files
    list(APPEND rawrtc_SOURCES
            crc32c.c
            sctp_redirect_transport.c)
endif ()

# Setup library (link & install)
add_library(rawrtc SHARED ${rawrtc_SOURCES})
target_link_libraries(rawrtc
        ${rawrtc_DEP_LIBRARIES})
add_library(rawrtc-static STATIC ${rawrtc_SOURCES})
target_link_libraries(rawrtc-static
        ${rawrtc_DEP_LIBRARIES})
install(TARGETS rawrtc rawrtc-static
        DESTINATION lib)

if (SCTP_REDIRECT_TRANSPORT)
    # And set the preprocessor variable
    target_compile_definitions(rawrtc PRIVATE SCTP_REDIRECT_TRANSPORT)
    target_compile_definitions(rawrtc-static PRIVATE SCTP_REDIRECT_TRANSPORT)
endif ()

# Generate pkg-config file & install it
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmakein
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
        DESTINATION lib/pkgconfig)
