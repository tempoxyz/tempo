variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

group "default" {
  targets = ["tempo", "tempo-bench", "tempo-sidecar", "tempo-xtask"]
}

target "docker-metadata" {}

# Base image with all dependencies pre-compiled
target "chef" {
  dockerfile = "Dockerfile.chef"
  context = "."
  platforms = ["linux/amd64"]
  args = {
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
  }
}

target "_common" {
  contexts = {
    chef = "target:chef"
  }
  args = {
    CHEF_IMAGE = "chef"
    RUST_PROFILE = "profiling"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
  platforms = ["linux/amd64"]
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  context = "."
  args = {
    RUST_BINARY = "tempo"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
  }
}

target "tempo-bench" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile.bench"
  context = "."
  args = {
    RUST_BINARY = "tempo-bench"
    RUST_FEATURES = ""
  }
}

target "tempo-sidecar" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  context = "."
  args = {
    RUST_BINARY = "tempo-sidecar"
    RUST_FEATURES = ""
  }
}

target "tempo-xtask" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  context = "."
  args = {
    RUST_BINARY = "tempo-xtask"
    RUST_FEATURES = ""
  }
}
