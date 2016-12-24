# Library sources
rawrtc_sources = [
    'ice_candidate.c',
    'ice_gatherer.c',
    'main.c',
    'utils.c',
]

# Setup library (link & install)
lib_rawrtc = library(
    'rawrtc',
    rawrtc_sources,
    include_directories: rawrtc_includes,
    dependencies: rawrtc_dependencies,
    install: true
)

