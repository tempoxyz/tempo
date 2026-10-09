// Override targets for profiling builds with frame pointers enabled
// Variables inherited from docker/docker-bake.hcl when files are merged

variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

target "chef" {
  dockerfile = "docker/Dockerfile.chef"
  context = "."
  platforms = ["linux/amd64"]
  args = {
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "jemalloc"
    EXTRA_RUSTFLAGS = "-C force-frame-pointers=yes"
  }
}

target "_common" {
  dockerfile = "docker/Dockerfile"
  context = "."
  contexts = {
    chef = "target:chef"
  }
  args = {
    CHEF_IMAGE = "chef"
    RUST_PROFILE = "profiling"
    EXTRA_RUSTFLAGS = "-C force-frame-pointers=yes"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
  platforms = ["linux/amd64"]
}

target "tempo-zone" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-zone"
}
