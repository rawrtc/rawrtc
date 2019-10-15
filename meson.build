# Project definition
project('rawrtc', 'c',
    version: '0.5.1',
    default_options: ['c_std=c99'],
    meson_version: '>=0.48.0')

# Set compiler warning flags
compiler = meson.get_compiler('c')
compiler_args = compiler.get_supported_arguments([
    '-Wall',
    '-Wmissing-declarations',
    '-Wmissing-prototypes',
    '-Wstrict-prototypes',
    '-Wbad-function-cast',
    '-Wsign-compare',
    '-Wnested-externs',
    '-Wshadow',
    '-Waggregate-return',
    '-Wcast-align',
    '-Wextra',
    '-Wold-style-definition',
    '-Wdeclaration-after-statement',
    '-Wuninitialized',
    '-Wshorten-64-to-32',
    '-pedantic',
])
add_project_arguments(compiler_args, language: 'c')

# Configuration
configuration = configuration_data()

# Dependency: OpenSSL
openssl_dep = dependency('openssl',
    version: '>=1.0.2',
    required: true)

# Dependency: re
# Note: We need to force using our own fork until re has accepted all our patches
re_dep = dependency('librawrre',
    version: '>=0.6.0',
    fallback: ['re', 're_dep'],
    required: true)

# Dependency: rew
rew_dep = dependency('librawrrew',
    version: '>=0.5.0',
    fallback: ['rew', 'rew_dep'],
    required: true)

# Dependency: rawrtcc
rawrtcc_dep = dependency('rawrtcc',
    version: '>=0.1.3',
    fallback: ['rawrtcc', 'rawrtcc_dep'],
    required: true)

# Dependency: rawrtcdc
rawrtcdc_dep = dependency('rawrtcdc',
    version: '>=0.1.3',
    fallback: ['rawrtcdc', 'rawrtcdc_dep'],
    required: true)

# Dependencies list
dependencies = [
    openssl_dep,
    re_dep,
    rew_dep,
    rawrtcc_dep,
    rawrtcdc_dep,
]

# Options
configuration.set10('RAWRTC_HAVE_SCTP_REDIRECT_TRANSPORT', get_option('sctp_redirect_transport'))

# Version
version = meson.project_version()
version_array = version.split('.')
configuration.set_quoted('RAWRTC_VERSION', version)
configuration.set('RAWRTC_VERSION_MAJOR', version_array[0])
configuration.set('RAWRTC_VERSION_MINOR', version_array[1])
configuration.set('RAWRTC_VERSION_PATCH', version_array[2])

# Set debug level
configuration.set('RAWRTC_DEBUG_LEVEL', get_option('debug_level'))

# Includes
include_dir = include_directories('include')
subdir('include')

# Sources
subdir('src')

# Build library
rawrtc = library(meson.project_name(), sources,
    dependencies: dependencies,
    include_directories: include_dir,
    install: true,
    version: version)

# Generate pkg-config file
pkg = import('pkgconfig')
pkg.generate(rawrtc,
    name: meson.project_name(),
    description: 'A WebRTC and ORTC library with a small footprint.',
    url: 'https://github.com/rawrtc/rawrtc')

# Declare dependency
rawrtc_dep = declare_dependency(
    include_directories: include_dir,
    link_with: rawrtc)

# Tools (optional)
if get_option('tools')
    subdir('tools')
endif
