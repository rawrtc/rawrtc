# Tool: ice-gatherer
add_executable(ice-gatherer ice-gatherer.c)
target_link_libraries(ice-gatherer
        rawrtc
        ${rawrtc_DEP_LIBRARIES})
install(TARGETS ice-gatherer
        DESTINATION bin)

# Tool: ice-transport
add_executable(ice-transport ice-transport.c)
target_link_libraries(ice-transport
        rawrtc)
install(TARGETS ice-transport
        DESTINATION bin)

# Tool: dtls-transport
add_executable(dtls-transport dtls-transport.c)
target_link_libraries(dtls-transport
        rawrtc)
install(TARGETS dtls-transport
        DESTINATION bin)

# Tool: redirect-transport-interop
add_executable(redirect-transport redirect-transport-interop.c)
target_link_libraries(redirect-transport
        rawrtc)
install(TARGETS redirect-transport
        DESTINATION bin)

# Tool: sctp-transport
add_executable(sctp-transport sctp-transport.c)
target_link_libraries(sctp-transport
        rawrtc)
install(TARGETS sctp-transport
        DESTINATION bin)

# Tool: data-channel-sctp
add_executable(data-channel-sctp data-channel-sctp.c)
target_link_libraries(data-channel-sctp
        rawrtc)
install(TARGETS data-channel-sctp
        DESTINATION bin)

# Tool: data-channel-interop
add_executable(data-channel-interop data-channel-interop.c)
target_link_libraries(data-channel-interop
        rawrtc)
install(TARGETS data-channel-interop
        DESTINATION bin)

