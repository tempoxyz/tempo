// Opt-in temporary devnet builds retain the normal release build by default.
variable "BUILD_SCOPE" {
  default = "all"
  validation {
    condition = contains(["all", "devnet"], BUILD_SCOPE)
    error_message = "BUILD_SCOPE must be all or devnet."
  }
}

variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

group "default" {
  targets = ["tempo", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

group "nightly" {
  targets = ["tempo", "tempo-localnet", "tempo-sidecar", "tempo-xtask"]
}

group "devnet" {
  targets = ["tempo", "tempo-xtask"]
}

target "docker-metadata" {}

# Base image with all dependencies pre-compiled
target "chef" {
  dockerfile = "Dockerfile.chef"
  context = "."
  platforms = BUILD_SCOPE == "devnet" ? ["linux/amd64"] : ["linux/amd64", "linux/arm64"]
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
    BUILD_SCOPE = BUILD_SCOPE
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
  }
  platforms = BUILD_SCOPE == "devnet" ? ["linux/amd64"] : ["linux/amd64", "linux/arm64"]
}

target "tempo" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo"
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
