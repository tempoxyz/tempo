#!/usr/bin/env bash

set -euo pipefail

WORKSPACE="${1:?Usage: $0 <workspace> [cooldown-config]}"
CONFIG_SOURCE="${2:-}"
COOLDOWN_DAYS="${CARGO_COOLDOWN_DAYS:-7}"

if [[ ! "$COOLDOWN_DAYS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: CARGO_COOLDOWN_DAYS must be a positive whole number" >&2
  exit 1
fi

if ! command -v cargo-cooldown >/dev/null 2>&1; then
  echo "ERROR: cargo-cooldown is required but is not installed" >&2
  exit 1
fi

WORKSPACE="$(cd "$WORKSPACE" && pwd)"
LOCKFILE="$WORKSPACE/Cargo.lock"
if [[ ! -f "$LOCKFILE" ]]; then
  echo "ERROR: Cargo.lock not found in $WORKSPACE" >&2
  exit 1
fi

LOCKFILE_SNAPSHOT="$(mktemp)"
cp "$LOCKFILE" "$LOCKFILE_SNAPSHOT"

CONFIG_TARGET="$WORKSPACE/cooldown.toml"
CONFIG_SNAPSHOT=""
CONFIG_WAS_PRESENT=false
CONFIG_REPLACED=false

cleanup() {
  if ! cmp -s "$LOCKFILE_SNAPSHOT" "$LOCKFILE"; then
    cp "$LOCKFILE_SNAPSHOT" "$LOCKFILE"
  fi
  rm -f "$LOCKFILE_SNAPSHOT"

  if [[ "$CONFIG_REPLACED" == "true" ]]; then
    if [[ "$CONFIG_WAS_PRESENT" == "true" ]]; then
      cp "$CONFIG_SNAPSHOT" "$CONFIG_TARGET"
    else
      rm -f "$CONFIG_TARGET"
    fi
    rm -f "$CONFIG_SNAPSHOT"
  fi
}
trap cleanup EXIT

if [[ -n "$CONFIG_SOURCE" ]]; then
  CONFIG_SOURCE="$(cd "$(dirname "$CONFIG_SOURCE")" && pwd)/$(basename "$CONFIG_SOURCE")"
  if [[ ! -f "$CONFIG_SOURCE" ]]; then
    echo "ERROR: cooldown config not found at $CONFIG_SOURCE" >&2
    exit 1
  fi
  if [[ ! -e "$CONFIG_TARGET" || ! "$CONFIG_SOURCE" -ef "$CONFIG_TARGET" ]]; then
    CONFIG_REPLACED=true
    if [[ -f "$CONFIG_TARGET" ]]; then
      CONFIG_WAS_PRESENT=true
      CONFIG_SNAPSHOT="$(mktemp)"
      cp "$CONFIG_TARGET" "$CONFIG_SNAPSHOT"
    fi
    cp "$CONFIG_SOURCE" "$CONFIG_TARGET"
  fi
fi

echo "Checking Cargo dependency cooldown in $WORKSPACE"
set +e
(
  cd "$WORKSPACE"
  export CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="${COOLDOWN_DAYS} days"
  export COOLDOWN_INCOMPATIBLE_PUBLISH_AGE=deny
  export COOLDOWN_LOCKFILE_BASELINE=ignore
  export RUSTC_WRAPPER=""
  cargo cooldown --workspace --all-features tree --locked --depth 0 >/dev/null
)
status=$?
set -e

if ! cmp -s "$LOCKFILE_SNAPSHOT" "$LOCKFILE"; then
  echo "ERROR: cargo-cooldown changed $LOCKFILE; refusing the unchecked graph" >&2
  exit 1
fi

if [[ "$status" -ne 0 ]]; then
  echo "ERROR: Cargo dependency cooldown failed in $WORKSPACE" >&2
  exit "$status"
fi
