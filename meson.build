# Project
project('rawrtc', 'c', version: '0.0.1')
compiler = meson.get_compiler('c')
rawrtc_dependencies = []

# Dependencies
prefix = get_option('prefix')
lib_zf_log = compiler.find_library('zf_log', dirs: prefix + '/lib')
lib_re = dependency('libre', version: '>=0.4.15')
lib_rew = dependency('librew', version: '>=0.4.0')
lib_usrsctp = compiler.find_library('libusrsctp', dirs: prefix + '/lib')
rawrtc_dependencies = [lib_zf_log, lib_re, lib_rew, lib_usrsctp]
rawrtc_includes = [
    include_directories(prefix + '/include'),
    # TODO: Remove as soon as you found out how to access the corresponding parts
    #       without having to use the internal interface to ICE
    include_directories(prefix + '/../dependencies/re/src/ice')
]

# Walk through subdirectories
subdir('src')

# Generate pkg entry
pkg_mod = import('pkgconfig')
pkg_mod.generate(
    libraries: lib_rawrtc,
    version: '0.0.1',  # TODO: Get version number from project
    name: 'librawrtc',
    filebase: 'rawrtc',
    description: 'WebRTC and ORTC library.'
)

