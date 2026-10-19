#!/usr/bin/env bash
# Compare the executables in candidate images with independent rebuild hashes.
set -euo pipefail
: "${IMAGE_DIR:?IMAGE_DIR is required}"
: "${GITHUB_RUN_ATTEMPT:?GITHUB_RUN_ATTEMPT is required}"
artifact_attempt="${ARTIFACT_RUN_ATTEMPT:-$GITHUB_RUN_ATTEMPT}"
cd "$IMAGE_DIR"
rm -f verified.sha256
container=""
trap '[[ -z "$container" ]] || docker rm -f "$container" >/dev/null' EXIT
for arch in amd64 arm64; do
  candidate="docker-candidate-$arch-$artifact_attempt"
  clean="docker-clean-$arch-$artifact_attempt"
  devnet="docker-clean-devnet-$arch-$artifact_attempt"
  extracted="$(mktemp -d)"
  for image in tempo tempo-devnet tempo-localnet tempo-sidecar tempo-xtask; do
    docker load --input "$candidate/$image.tar"
    container="$(docker create --platform "linux/$arch" "$image:candidate-$arch")"
    binary="$image"
    [[ "$image" != tempo-devnet ]] || binary=tempo
    docker cp "$container:/usr/local/bin/$binary" "$extracted/$image"
    # The localnet image also ships a tempo executable; check both copies.
    if [[ "$image" == tempo-localnet ]]; then
      docker cp "$container:/usr/local/bin/tempo" "$extracted/localnet-tempo"
      cmp "$extracted/tempo" "$extracted/localnet-tempo"
    fi
    docker rm -f "$container" >/dev/null
    container=""
  done
  cat "$clean/clean.sha256" "$devnet/clean.sha256" > "$extracted/expected.sha256"
  # Missing, duplicate, or unexpected entries must never weaken the gate.
  diff <(printf '%s\n' tempo tempo-devnet tempo-localnet tempo-sidecar tempo-xtask) \
    <(awk '{print $2}' "$extracted/expected.sha256" | LC_ALL=C sort)
  (cd "$extracted" && sha256sum --check expected.sha256)
  rm -rf "$extracted"
done
# Bind promotion to these exact archives, including their runtime files/labels.
sha256sum docker-candidate-*/*.tar > verified.sha256
