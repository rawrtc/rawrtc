# Walk through subdirectories
add_subdirectory(helper)

# Tool: ice-gatherer
add_executable(ice-gatherer
        ice-gatherer.c)
target_link_libraries(ice-gatherer
        rawrtc
        rawrtc-helper)
install(TARGETS ice-gatherer
        DESTINATION bin)

## Tool: ice-transport-loopback
add_executable(ice-transport-loopback
        ice-transport-loopback.c)
target_link_libraries(ice-transport-loopback
        rawrtc
        rawrtc-helper)
install(TARGETS ice-transport-loopback
        DESTINATION bin)

# Tool: dtls-transport-loopback
add_executable(dtls-transport-loopback
        dtls-transport-loopback.c)
target_link_libraries(dtls-transport-loopback
        rawrtc
        rawrtc-helper)
install(TARGETS dtls-transport-loopback
        DESTINATION bin)

# Tool: sctp-redirect-transport
if (SCTP_REDIRECT_TRANSPORT)
  message(STATUS "Configuring for build with SCTP redirect transport.")
  add_executable(sctp-redirect-transport
          sctp-redirect-transport.c)
  target_link_libraries(sctp-redirect-transport
          rawrtc
          rawrtc-helper)
  install(TARGETS sctp-redirect-transport
          DESTINATION bin)
  target_compile_definitions(sctp-redirect-transport PRIVATE SCTP_REDIRECT_TRANSPORT)
endif ()

# Tool: sctp-transport-loopback
add_executable(sctp-transport-loopback
        sctp-transport-loopback.c)
target_link_libraries(sctp-transport-loopback
        rawrtc
        rawrtc-helper)
install(TARGETS sctp-transport-loopback
        DESTINATION bin)

# Tool: data-channel-sctp-loopback
add_executable(data-channel-sctp-loopback
        data-channel-sctp-loopback.c)
target_link_libraries(data-channel-sctp-loopback
        rawrtc
        rawrtc-helper)
install(TARGETS data-channel-sctp-loopback
        DESTINATION bin)

# Tool: data-channel-sctp
add_executable(data-channel-sctp
        data-channel-sctp.c)
target_link_libraries(data-channel-sctp
        rawrtc
        rawrtc-helper)
install(TARGETS data-channel-sctp
        DESTINATION bin)

# Tool: data-channel-sctp-echo
add_executable(data-channel-sctp-echo
        data-channel-sctp-echo.c)
target_link_libraries(data-channel-sctp-echo
        rawrtc
        rawrtc-helper)
install(TARGETS data-channel-sctp-echo
        DESTINATION bin)

# Tool: data-channel-sctp-streamed
add_executable(data-channel-sctp-streamed
        data-channel-sctp-streamed.c)
target_link_libraries(data-channel-sctp-streamed
        rawrtc
        rawrtc-helper)
install(TARGETS data-channel-sctp-streamed
        DESTINATION bin)

# Tool: data-channel-sctp-throughput
add_executable(data-channel-sctp-throughput
        data-channel-sctp-throughput.c)
target_link_libraries(data-channel-sctp-throughput
        rawrtc
        rawrtc-helper)
install(TARGETS data-channel-sctp-throughput
        DESTINATION bin)

# Tool: peer-connection
add_executable(peer-connection
        peer-connection.c)
target_link_libraries(peer-connection
        rawrtc
        rawrtc-helper)
install(TARGETS peer-connection
        DESTINATION bin)
