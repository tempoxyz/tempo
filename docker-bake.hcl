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

target "_common" {
  context = "."
  platforms = ["linux/amd64"]
  args = {
    RUST_PROFILE = "profiling"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  args = {
    RUST_BINARY = "tempo"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
  }
  tags = []
}

target "tempo-bench" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile.bench"
  args = {
    RUST_BINARY = "tempo-bench"
    RUST_FEATURES = ""
  }
  tags = []
}

target "tempo-sidecar" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  args = {
    RUST_BINARY = "tempo-sidecar"
    RUST_FEATURES = ""
  }
  tags = []
}

target "tempo-xtask" {
  inherits = ["_common", "docker-metadata"]
  dockerfile = "Dockerfile"
  args = {
    RUST_BINARY = "tempo-xtask"
    RUST_FEATURES = ""
  }
  tags = []
}
