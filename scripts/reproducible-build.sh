#!/usr/bin/env bash
# Reproducible-build wrapper. Single source of truth for how the byte-deterministic
# Linux `tempo` / `tempo-sidecar` binary is produced from this checkout.
#
# Called identically by:
#   * .github/workflows/reproducible-build.yml (push-on-main canary +
#     manual workflow_dispatch), release.yml, and independent rebuild jobs
#   * any independent rebuilder verifying a release hash from outside CI
#
# Keeping the docker invocation here — instead of inlined in each caller —
# means the in-CI hash and the independent-rebuilder hash can never
# silently diverge through someone editing one site and forgetting the
# other.
#
# Inputs (env):
#   VERSION       — informational tag baked into the build context (default: dev)
#   OUT_DIR       — where the built binary lands (default: ./out)
#   DEBIAN_SNAPSHOT — pin the Debian apt snapshot used inside the image
#                     (default: the value baked into Dockerfile.reproducible)
#
# Additional inputs: PLATFORM (linux/amd64 or linux/arm64), BINARY (tempo or
# tempo-sidecar), FEATURES (including an empty string), NO_CACHE (0 or 1).
#
# Output:
#   $OUT_DIR/$BINARY   — the byte-deterministic binary
#   stdout           — the inputs that determined this build, for audit logs
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION="${VERSION:-dev}"
OUT_DIR="${OUT_DIR:-./out}"
DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-}"
PLATFORM="${PLATFORM:-linux/amd64}"
BINARY="${BINARY:-tempo}"
FEATURES="${FEATURES-asm-keccak,jemalloc,otlp}"
NO_CACHE="${NO_CACHE:-0}"
[[ "$PLATFORM" == linux/amd64 || "$PLATFORM" == linux/arm64 ]]
[[ "$BINARY" == tempo || "$BINARY" == tempo-sidecar ]]
[[ "$NO_CACHE" == 0 || "$NO_CACHE" == 1 ]]
cache_args=()
if [[ "$NO_CACHE" == 1 ]]; then cache_args+=(--no-cache --pull); fi

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
COMMIT="$(git rev-parse HEAD)"

# Audit-friendly summary of the inputs that determine the resulting hash.
# A rebuilder comparing hashes that don't match should diff this block first.
echo "::group::Reproducible build inputs"
printf '  commit              = %s\n' "$COMMIT"
printf '  version             = %s\n' "$VERSION"
printf '  SOURCE_DATE_EPOCH   = %s\n' "$SOURCE_DATE_EPOCH"
printf '  Dockerfile          = Dockerfile.reproducible\n'
printf '  out_dir             = %s\n' "$OUT_DIR"
[[ -n "$DEBIAN_SNAPSHOT" ]] && printf '  DEBIAN_SNAPSHOT     = %s (override)\n' "$DEBIAN_SNAPSHOT"
echo "::endgroup::"

mkdir -p "$OUT_DIR"

build_args=(
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
  --build-arg "VERSION=$VERSION"
  --build-arg "BINARY=$BINARY"
  --build-arg "FEATURES=$FEATURES"
)
if [[ -n "${CARGO_BUILD_JOBS:-}" ]]; then
  build_args+=(--build-arg "CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS")
fi
if [[ -n "$DEBIAN_SNAPSHOT" ]]; then
  build_args+=( --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" )
fi

docker buildx build \
  --platform "$PLATFORM" \
  "${cache_args[@]}" \
  "${build_args[@]}" \
  -f Dockerfile.reproducible \
  --target artifacts \
  --output "type=local,dest=$OUT_DIR" \
  .

echo "Reproducible binary written to $OUT_DIR/$BINARY"
sha256sum "$OUT_DIR/$BINARY"
