# Tool: ice-gatherer
add_executable(ice-gatherer ice-gatherer.c)
target_link_libraries(ice-gatherer
        anyrtc)
install(TARGETS ice-gatherer
        DESTINATION bin)

# Tool: redirect-sctp
add_executable(redirect-sctp redirect-sctp.c)
target_link_libraries(redirect-sctp
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS redirect-sctp
        DESTINATION bin)
