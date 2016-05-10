project('anyrtc', 'c')
compiler = meson.get_compiler('c')
anyrtc_dependencies = []

prefix = get_option('prefix')
lib_zf_log = compiler.find_library('zf_log', dirs: prefix + '/lib')
lib_re = dependency('libre', version: '>=0.4.15')
lib_rew = dependency('librew', version: '>=0.4.0')
anyrtc_dependencies = [lib_zf_log, lib_re, lib_rew]
anyrtc_includes = [
    include_directories(prefix + '/include'),
    # TODO: Remove as soon as you found out how to access the corresponding parts
    #       without having to use the internal interface to ICE
    include_directories(prefix + '/../dependencies/re/src/ice')
]

subdir('src')

pkg_mod = import('pkgconfig')
pkg_mod.generate(
    libraries: lib_anyrtc,
    version: '0.0.1',
    name: 'libanyrtc',
    filebase: 'anyrtc',
    description: 'WebRTC and ORTC library.'
)

