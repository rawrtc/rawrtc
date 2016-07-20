# Setup tools (link & install)
add_executable(redirect-sctp redirect-sctp.c)
target_link_libraries(redirect-sctp
        ${anyrtc_DEP_LIBRARIES})
install(TARGETS redirect-sctp
        DESTINATION bin)
