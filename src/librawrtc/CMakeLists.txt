# Library sources
set(rawrtc_SOURCES
        candidate_helper.c
        config.c
        dtls_parameters.c
        dtls_transport.c
        ice_candidate.c
        ice_gather_options.c
        ice_gatherer.c
        ice_parameters.c
        ice_server.c
        ice_transport.c
        main.c
        peer_connection.c
        peer_connection_configuration.c
        peer_connection_description.c
        peer_connection_ice_candidate.c
        peer_connection_states.c
        sctp_transport.c)

# Library internal headers
set(rawrtc_HEADERS
        candidate_helper.h
        config.h
        dtls_parameters.h
        dtls_transport.h
        ice_candidate.h
        ice_gather_options.h
        ice_gatherer.h
        ice_parameters.h
        ice_server.h
        ice_transport.h
        main.h
        peer_connection.h
        peer_connection_configuration.h
        peer_connection_description.h
        peer_connection_ice_candidate.h
        peer_connection_states.h
        sctp_transport.h)

# Setup library (link & install)
add_library(rawrtc SHARED ${rawrtc_SOURCES})
target_link_libraries(rawrtc
        ${rawrtc_DEP_LIBRARIES})
add_library(rawrtc-static STATIC ${rawrtc_SOURCES})
target_link_libraries(rawrtc-static
        ${rawrtc_DEP_LIBRARIES})
install(TARGETS rawrtc rawrtc-static
        DESTINATION lib)

# Generate internal headers & install them
set(internal_header_file "${CMAKE_SOURCE_DIR}/src/include/rawrtc_internal.h")
set(rawrtc_HEADERS_INCLUDE "")
foreach (header IN LISTS rawrtc_HEADERS)
    string(CONCAT rawrtc_HEADERS_INCLUDE
            ${rawrtc_HEADERS_INCLUDE}
            "#include <rawrtc/internal/"
            ${header} ">\n")
endforeach ()
configure_file(${CMAKE_SOURCE_DIR}/src/include/rawrtc_internal.h.cmakein
        ${internal_header_file} @ONLY)
install(FILES ${rawrtc_HEADERS} DESTINATION include/rawrtc/internal)
install(FILES ${internal_header_file} DESTINATION include)

# Generate pkg-config file & install it
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/pkg-config.pc.cmakein
        ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc
        DESTINATION lib/pkgconfig)
