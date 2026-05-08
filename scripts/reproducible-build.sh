#!/usr/bin/env bash
# Reproducible-build wrapper. Single source of truth for how the byte-deterministic
# `tempo` binary on x86_64/aarch64-unknown-linux-gnu is produced from this checkout.
#
# Called identically by:
#   * .github/workflows/reproducible-build.yml (push-on-main canary +
#     manual workflow_dispatch; future workflow_call from release.yml)
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
# Output:
#   $OUT_DIR/tempo   — the byte-deterministic binary
#   stdout           — the inputs that determined this build, for audit logs
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

VERSION="${VERSION:-dev}"
OUT_DIR="${OUT_DIR:-./out}"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"
DEBIAN_SNAPSHOT="${DEBIAN_SNAPSHOT:-}"

# Derive docker platform and jemalloc cross-compile arch from TARGET.
if [[ "$TARGET" == *aarch64* ]]; then
  DOCKER_PLATFORM="linux/arm64"
  JEMALLOC_ARCH="aarch64-linux-gnu"
else
  DOCKER_PLATFORM="linux/amd64"
  JEMALLOC_ARCH="x86_64-linux-gnu"
fi

SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
COMMIT="$(git rev-parse HEAD)"

# Audit-friendly summary of the inputs that determine the resulting hash.
# A rebuilder comparing hashes that don't match should diff this block first.
echo "::group::Reproducible build inputs"
printf '  commit              = %s\n' "$COMMIT"
printf '  version             = %s\n' "$VERSION"
printf '  target              = %s\n' "$TARGET"
printf '  SOURCE_DATE_EPOCH   = %s\n' "$SOURCE_DATE_EPOCH"
printf '  Dockerfile          = Dockerfile.reproducible\n'
printf '  out_dir             = %s\n' "$OUT_DIR"
[[ -n "$DEBIAN_SNAPSHOT" ]] && printf '  DEBIAN_SNAPSHOT     = %s (override)\n' "$DEBIAN_SNAPSHOT"
echo "::endgroup::"

mkdir -p "$OUT_DIR"

build_args=(
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
  --build-arg "VERSION=$VERSION"
  --build-arg "TARGET=$TARGET"
  --build-arg "JEMALLOC_ARCH=$JEMALLOC_ARCH"
)
if [[ -n "$DEBIAN_SNAPSHOT" ]]; then
  build_args+=( --build-arg "DEBIAN_SNAPSHOT=$DEBIAN_SNAPSHOT" )
fi

docker build \
  --platform "$DOCKER_PLATFORM" \
  "${build_args[@]}" \
  -f Dockerfile.reproducible \
  --target artifacts \
  --output "type=local,dest=$OUT_DIR" \
  .

echo "Reproducible binary written to $OUT_DIR/tempo"
sha256sum "$OUT_DIR/tempo"
