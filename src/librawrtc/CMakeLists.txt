# Library sources
set(rawrtc_SOURCES
        candidate_helper.c
        certificate.c
        config.c
        diffie_hellman_parameters.c
        dtls_parameters.c
        dtls_transport.c
        ice_candidate.c
        ice_gather_options.c
        ice_gatherer.c
        ice_parameters.c
        ice_server.c
        ice_server_url_address.c
        ice_server_url_resolver.c
        ice_transport.c
        main.c
        peer_connection.c
        peer_connection_configuration.c
        peer_connection_description.c
        peer_connection_ice_candidate.c
        peer_connection_states.c
        sctp_common.c
        sctp_transport.c
        utils.c)

# Library internal headers
set(rawrtc_HEADERS
        candidate_helper.h
        certificate.h
        config.h
        dtls_parameters.h
        dtls_transport.h
        ice_candidate.h
        ice_gather_options.h
        ice_gatherer.h
        ice_parameters.h
        ice_server.h
        ice_server_url_address.h
        ice_server_url_resolver.h
        ice_transport.h
        main.h
        peer_connection.h
        peer_connection_configuration.h
        peer_connection_description.h
        peer_connection_ice_candidate.h
        peer_connection_states.h
        sctp_common.h
        sctp_transport.h
        utils.h)

# Optional: SCTP redirect transport tool sources
if (SCTP_REDIRECT_TRANSPORT)
    list(APPEND rawrtc_SOURCES
            sctp_redirect_transport.c)
    list(APPEND rawrtc_HEADERS
            sctp_redirect_transport.h)
endif ()

# Setup library (link & install)
add_library(rawrtc ${rawrtc_SOURCES})
set_property(TARGET rawrtc
        PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(rawrtc
        ${rawrtc_DEP_LIBRARIES})
install(TARGETS rawrtc
        DESTINATION lib)

# Optional: SCTP redirect transport tool definitions
if (SCTP_REDIRECT_TRANSPORT)
    # And set the preprocessor variable
    target_compile_definitions(rawrtc PRIVATE SCTP_REDIRECT_TRANSPORT)
endif ()

# Install internal headers
install(FILES ${rawrtc_HEADERS} DESTINATION include/rawrtc/internal)

# Generate pkg-config file & install it
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmakein
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
        DESTINATION lib/pkgconfig)
