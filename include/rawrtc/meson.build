# Generate configuration header
configure_file(
    input: 'config.h.in',
    output: 'config.h',
    configuration: configuration,
    install_dir: '/'.join([get_option('includedir'), 'rawrtc']))

# Install headers
includes = files([
    'certificate.h',
    'dtls_fingerprint.h',
    'dtls_parameters.h',
    'dtls_transport.h',
    'ice_candidate.h',
    'ice_gather_options.h',
    'ice_gatherer.h',
    'ice_parameters.h',
    'ice_server.h',
    'ice_transport.h',
    'main.h',
    'peer_connection.h',
    'peer_connection_configuration.h',
    'peer_connection_description.h',
    'peer_connection_ice_candidate.h',
    'peer_connection_state.h',
    'sctp_transport.h',
    'utils.h',
])
if get_option('sctp_redirect_transport')
    includes += files('sctp_redirect_transport.h')
endif
install_headers(includes, subdir: 'rawrtc')
