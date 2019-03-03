# Build helper library
subdir('helper')
rawrtc_helper = static_library('rawrtc-helper', helper_sources,
    dependencies: dependencies,
    include_directories: include_dir)

# Tools and their sources
tools = {
    'data-channel-sctp': files('data-channel-sctp.c'),
    'data-channel-sctp-echo': files('data-channel-sctp-echo.c'),
    'data-channel-sctp-loopback': files('data-channel-sctp-loopback.c'),
    'data-channel-sctp-streamed': files('data-channel-sctp-streamed.c'),
    'data-channel-sctp-throughput': files('data-channel-sctp-throughput.c'),
    'dtls-transport-loopback': files('dtls-transport-loopback.c'),
    'ice-gatherer': files('ice-gatherer.c'),
    'ice-transport-loopback': files('ice-transport-loopback.c'),
    'peer-connection': files('peer-connection.c'),
}
if get_option('sctp_redirect_transport')
    tools += {'sctp-redirect-transport': files('sctp-redirect-transport.c')}
endif

# Build executables
foreach name, sources : tools
    executable(
        name,
        sources,
        dependencies: [re_dep, rawrtcc_dep, rawrtcdc_dep],
        include_directories: include_dir,
        install: true,
        link_with: [rawrtc, rawrtc_helper])
endforeach
