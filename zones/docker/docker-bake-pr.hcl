// Pull request override, merged after zones/docker/docker-bake.hcl.
// PR builds skip the fat-LTO zones-reproducible tempo-zone build: they publish
// the profiling binary that the tempo-zone-xtask builder stage already
// compiles. Merge queue, main, schedules and releases keep the reproducible
// image and its verification.

target "tempo-zone" {
  dockerfile = "zones/docker/Dockerfile"
  target = "tempo-zone"
  contexts = {
    chef = "target:chef"
  }
  args = {
    CHEF_IMAGE = "chef"
    RUST_PROFILE = "profiling"
    CACHE_FAMILY = "node"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
  labels = {
    "org.opencontainers.image.description" = "Pull request tempo-zone image (profiling build); not reproducible."
    "org.tempoxyz.reproducible.verification-scope" = "none"
  }
}
