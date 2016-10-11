# Library sources
anyrtc_sources = [
    'ice_candidate.c',
    'ice_gatherer.c',
    'main.c',
    'utils.c',
]

# Setup library (link & install)
lib_anyrtc = library(
    'anyrtc',
    anyrtc_sources,
    include_directories: anyrtc_includes,
    dependencies: anyrtc_dependencies,
    install: true
)

