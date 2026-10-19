variable "SOURCE_DATE_EPOCH" {
  default = ""
}

variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

group "default" {
  targets = ["tempo", "tempo-devnet", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

group "nightly" {
  targets = ["tempo", "tempo-devnet", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
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
  dockerfile = "Dockerfile.reproducible"
  context = "."
  args = {
    SOURCE_DATE_EPOCH = "${SOURCE_DATE_EPOCH}"
  }
  platforms = ["linux/amd64", "linux/arm64"]
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo"
}

target "tempo-devnet" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-devnet"
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
