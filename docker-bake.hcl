variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

variable "REGISTRY" {
  default = "ghcr.io/tempoxyz"
}

group "default" {
  targets = ["tempo", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

group "nightly" {
  targets = ["tempo-nightly", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

target "docker-metadata" {}

# Base image with all dependencies pre-compiled
target "chef" {
  dockerfile = "Dockerfile.chef"
  context = "."
  platforms = ["linux/amd64", "linux/arm64"]
  args = {
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
  }
}

target "_common" {
  dockerfile = "Dockerfile"
  context = "."
  contexts = {
    chef = "target:chef"
  }
  args = {
    CHEF_IMAGE = "chef"
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
  platforms = ["linux/amd64", "linux/arm64"]
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo"
}

target "tempo-nightly" {
  inherits = ["tempo"]
  args = {
    RETH_ENGINE_PERSISTENCE_THRESHOLD = "30"
    RETH_ENGINE_NUM_STATE_MASKING_BLOCKS = "20"
  }
  tags = ["${REGISTRY}/tempo:nightly", "docker.io/tempoxyz/tempo:nightly"]
}

target "tempo-localnet" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-localnet"
}

target "tempo-sidecar" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-sidecar"
}

target "tempo-xtask" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-xtask"
}
