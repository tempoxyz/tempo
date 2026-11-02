#!/usr/bin/env bash
# Shared production/verification packaging of the canonical prover executable.
# Required: PROVER_BINARY_DIR, BUILD_INPUT_FILE and EIF_BUILDER_IMAGE.
# Output: $OUT_DIR/enclave.eif and $OUT_DIR/measurements.json.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BUILD_BACKEND="${BUILD_BACKEND:-docker}"
NO_CACHE="${NO_CACHE:-0}"
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
GIT_SHA="${GIT_SHA:-$(git rev-parse HEAD)}"
OUT_DIR="${OUT_DIR:-./target/tempo-zone-prover-eif}"
PROVER_IMAGE="tempo-zone-prover-enclave:reproducible-${GIT_SHA}"
: "${PROVER_BINARY_DIR:?Set PROVER_BINARY_DIR}"
: "${BUILD_INPUT_FILE:?Set BUILD_INPUT_FILE}"
: "${EIF_BUILDER_IMAGE:?Set EIF_BUILDER_IMAGE}"
[[ "$NO_CACHE" == 0 || "$NO_CACHE" == 1 ]]
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ && "$GIT_SHA" =~ ^[0-9a-f]{40}$ ]]
# Private copies may build this fixed local tag without publishing a toolchain.
[[ "$EIF_BUILDER_IMAGE" =~ ^[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}$ ||
   "$EIF_BUILDER_IMAGE" == tempo-zone-prover-eif-builder:local ]]
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
mkdir "$scratch_dir/genesis" "$scratch_dir/binary"
chmod 0755 "$scratch_dir/genesis" "$scratch_dir/binary"
cp "$BUILD_INPUT_FILE" "$scratch_dir/genesis/genesis.json"
cp "$PROVER_BINARY_DIR/tempo-zone-prover-enclave" "$scratch_dir/binary/tempo-zone-prover-enclave"
chmod 0644 "$scratch_dir/genesis/genesis.json"
chmod 0755 "$scratch_dir/binary/tempo-zone-prover-enclave"
binary_sha256="$(sha256sum "$scratch_dir/binary/tempo-zone-prover-enclave" | cut -d' ' -f1)"
case "$BUILD_BACKEND" in
  docker)
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
"${build[@]}" --platform linux/amd64 \
  --file zones/docker/Dockerfile.prover-package \
  --build-context "prover-binary=$scratch_dir/binary" \
  --build-context "tempo-genesis=$scratch_dir/genesis" \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  --build-arg "PROVER_BINARY_SHA256=$binary_sha256" \
  --provenance=false --tag "$PROVER_IMAGE" \
  --output "type=docker,dest=$scratch_dir/enclave.tar,rewrite-timestamp=true" .
docker load --input "$scratch_dir/enclave.tar"
docker run --rm --platform linux/amd64 \
  --volume /var/run/docker.sock:/var/run/docker.sock \
  --volume "$OUT_DIR:/output" \
  "$EIF_BUILDER_IMAGE" build-enclave \
  --docker-uri "$PROVER_IMAGE" \
  --name tempo-zone-prover --version "$GIT_SHA" \
  --output-file /output/enclave.eif | tee "$OUT_DIR/measurements.json"
sha256sum "$OUT_DIR/enclave.eif"
