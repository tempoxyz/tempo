variable "VERGEN_GIT_SHA" {
  default = ""
}

variable "VERGEN_GIT_SHA_SHORT" {
  default = ""
}

# Appended to every target's features (such as ",corpus"). Network E2E builds set it so the
# merge queue can replay the corpus with the image it tests; other builds leave it empty.
variable "EXTRA_RUST_FEATURES" {
  default = ""
}

group "default" {
  targets = ["tempo", "tempo-devnet", "tempo-localnet", "tempo-xtask"]
}

group "nightly" {
  targets = ["tempo", "tempo-devnet", "tempo-localnet", "tempo-xtask", "tempo-fuzz"]
}

target "docker-metadata" {}

# Base image with all dependencies pre-compiled
target "chef" {
  dockerfile = "Dockerfile.chef"
  context = "."
  platforms = ["linux/amd64", "linux/arm64"]
  args = {
    RUST_PROFILE = "profiling"
    RUST_FEATURES = "asm-keccak,jemalloc,otlp${EXTRA_RUST_FEATURES}"
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
    RUST_FEATURES = "asm-keccak,jemalloc,otlp${EXTRA_RUST_FEATURES}"
    VERGEN_GIT_SHA = "${VERGEN_GIT_SHA}"
    VERGEN_GIT_SHA_SHORT = "${VERGEN_GIT_SHA_SHORT}"
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

target "tempo-xtask" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo-xtask"
}

# tempo with the corpus and fuzz features, for corpus replay and fuzzing jobs. Built only
# with the nightly and pushed as tempo:fuzz, so production images keep their features.
target "tempo-fuzz" {
  inherits = ["_common", "docker-metadata"]
  target = "tempo"
  args = {
    RUST_FEATURES = "asm-keccak,jemalloc,otlp,corpus,fuzz"
  }
}
