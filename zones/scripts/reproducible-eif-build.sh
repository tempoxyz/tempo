#!/usr/bin/env bash
# Build an unsigned prover EIF using a digest-pinned Nitro toolchain image.
# Required: EIF_BUILDER_IMAGE and BUILD_INPUT_FILE (verified Tempo genesis JSON).
# Optional: BUILD_BACKEND=docker|depot, DEPOT_PROJECT, NO_CACHE=0|1, OUT_DIR,
# SOURCE_DATE_EPOCH and GIT_SHA (both default to the checked-out commit).
# Output: $OUT_DIR/enclave.eif. The shared workflow independently measures it.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
BUILD_BACKEND="${BUILD_BACKEND:-docker}"
NO_CACHE="${NO_CACHE:-1}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
GIT_SHA="${GIT_SHA:-$(git rev-parse HEAD)}"
OUT_DIR="${OUT_DIR:-./target/reproducible-eif}"
: "${EIF_BUILDER_IMAGE:?Set EIF_BUILDER_IMAGE to the toolchain image@sha256:digest}"
: "${BUILD_INPUT_FILE:?Set BUILD_INPUT_FILE to the verified Tempo genesis JSON}"

[[ "$EIF_BUILDER_IMAGE" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ]]
[[ "$NO_CACHE" == 0 || "$NO_CACHE" == 1 ]]
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ && "$GIT_SHA" =~ ^[0-9a-f]{40}$ ]]
jq -e '.config.chainId | type == "number"' "$BUILD_INPUT_FILE" >/dev/null

mkdir -p "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"
scratch_dir="$(mktemp -d)"
builder_name=""
cleanup() {
  if [[ -n "$builder_name" ]]; then
    docker buildx rm "$builder_name" >/dev/null 2>&1 || true
  fi
  rm -rf "$scratch_dir"
}
trap cleanup EXIT
mkdir "$scratch_dir/binary"

case "$BUILD_BACKEND" in
  docker)
    # GitHub runners can use Docker's classic image store, whose default driver
    # cannot export a Docker archive. An isolated builder also starts empty.
    builder_name="$(docker buildx create --driver docker-container \
      --driver-opt image=moby/buildkit:v0.29.0@sha256:0039c1d47e8748b5afea56f4e85f14febaf34452bd99d9552d2daa82262b5cc5)"
    build=(docker buildx build --builder "$builder_name")
    ;;
  depot) build=(depot build --project "${DEPOT_PROJECT:?Set DEPOT_PROJECT}") ;;
  *) echo "BUILD_BACKEND must be docker or depot" >&2; exit 1 ;;
esac
if [[ "$NO_CACHE" == 1 ]]; then
  build+=(--no-cache)
fi

# Compile the same canonical executable exported by production before genesis.
"${build[@]}" \
  --platform linux/amd64 \
  --file zones/docker/Dockerfile.reproducible \
  --target prover-artifacts \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --build-arg "GIT_SHA=$GIT_SHA" \
  --build-arg "VERSION=sha-${GIT_SHA:0:7}" \
  --output "type=local,dest=$scratch_dir/binary" .
export BUILD_BACKEND NO_CACHE SOURCE_DATE_EPOCH GIT_SHA OUT_DIR
PROVER_BINARY_DIR="$scratch_dir/binary" zones/scripts/package-prover-eif.sh
