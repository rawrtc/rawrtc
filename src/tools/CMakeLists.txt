# Tool: ice-gatherer
add_executable(ice-gatherer ice-gatherer.c)
target_link_libraries(ice-gatherer
        anyrtc
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS ice-gatherer
        DESTINATION bin)

# Tool: ice-transport
add_executable(ice-transport ice-transport.c)
target_link_libraries(ice-transport
        anyrtc)
install(TARGETS ice-transport
        DESTINATION bin)

# Tool: dtls-transport
add_executable(dtls-transport dtls-transport.c)
target_link_libraries(dtls-transport
        anyrtc)
install(TARGETS dtls-transport
        DESTINATION bin)

# Tool: sctp-transport
add_executable(sctp-transport sctp-transport.c)
target_link_libraries(sctp-transport
        anyrtc)
install(TARGETS sctp-transport
        DESTINATION bin)

# Tool: redirect-sctp
add_executable(redirect-sctp redirect-sctp.c)
target_link_libraries(redirect-sctp
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS redirect-sctp
        DESTINATION bin)
