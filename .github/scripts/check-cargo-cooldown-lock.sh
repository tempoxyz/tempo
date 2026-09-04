#!/usr/bin/env bash

set -euo pipefail

WORKSPACE="${1:?Usage: $0 <workspace> <cooldown-config>}"
CONFIG_SOURCE="${2:?Usage: $0 <workspace> <cooldown-config>}"
COOLDOWN_DAYS="${CARGO_COOLDOWN_DAYS:-7}"

if [[ ! "$COOLDOWN_DAYS" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: CARGO_COOLDOWN_DAYS must be a positive whole number" >&2
  exit 1
fi

VERIFIER="${CARGO_COOLDOWN_BIN:-$(command -v cargo-cooldown || true)}"
if [[ -z "$VERIFIER" || ! -x "$VERIFIER" ]]; then
  echo "ERROR: cargo-cooldown is required but is not installed" >&2
  exit 1
fi

VERIFIER="$(cd "$(dirname "$VERIFIER")" && pwd)/$(basename "$VERIFIER")"
if [[ -n "${RUNNER_TEMP:-}" ]]; then
  case "$VERIFIER" in
    "$RUNNER_TEMP"/cargo-cooldown-*/bin/cargo-cooldown|"$RUNNER_TEMP"/cargo-cooldown-*/bin/cargo-cooldown.exe) ;;
    *)
      echo "ERROR: refusing cargo-cooldown outside the checksum-verified action directory: $VERIFIER" >&2
      exit 1
      ;;
  esac
fi

WORKSPACE="$(cd "$WORKSPACE" && pwd)"
LOCKFILE="$WORKSPACE/Cargo.lock"
if [[ ! -f "$LOCKFILE" ]]; then
  echo "ERROR: Cargo.lock not found in $WORKSPACE" >&2
  exit 1
fi

LOCKFILE_SNAPSHOT="$(mktemp)"
cp "$LOCKFILE" "$LOCKFILE_SNAPSHOT"
ISOLATED_CARGO_HOME="$(mktemp -d)"

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

  rm -rf "$ISOLATED_CARGO_HOME"
}
trap cleanup EXIT

CONFIG_SOURCE="$(cd "$(dirname "$CONFIG_SOURCE")" && pwd)/$(basename "$CONFIG_SOURCE")"
if [[ ! -f "$CONFIG_SOURCE" ]]; then
  echo "ERROR: cooldown config not found at $CONFIG_SOURCE" >&2
  exit 1
fi

CONFIG_LOCKFILE="$(dirname "$CONFIG_SOURCE")/Cargo.lock"
if [[ -f "$CONFIG_LOCKFILE" ]]; then
  while IFS=$'\t' read -r crate version; do
    if ! awk -v expected_name="$crate" -v expected_version="$version" '
      /^\[\[package\]\]$/ { name = ""; version = "" }
      /^name = "/ { name = $0; sub(/^name = "/, "", name); sub(/"$/, "", name) }
      /^version = "/ { version = $0; sub(/^version = "/, "", version); sub(/"$/, "", version) }
      name == expected_name && version == expected_version { found = 1 }
      END { exit found ? 0 : 1 }
    ' "$CONFIG_LOCKFILE"; then
      echo "ERROR: cooldown exception $crate@$version is not present in $CONFIG_LOCKFILE" >&2
      exit 1
    fi
  done < <(awk '
    /^\[\[allow\.exact\]\]$/ { exact = 1; crate = ""; next }
    /^\[/ { exact = 0 }
    exact && /^crate = "/ { crate = $0; sub(/^crate = "/, "", crate); sub(/"$/, "", crate) }
    exact && /^version = "/ {
      version = $0; sub(/^version = "/, "", version); sub(/"$/, "", version)
      if (crate != "") print crate "\t" version
    }
  ' "$CONFIG_SOURCE")
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

ORIGINAL_CARGO_HOME="${CARGO_HOME:-${HOME:?HOME is required}/.cargo}"
for directory in registry git; do
  if [[ -e "$ORIGINAL_CARGO_HOME/$directory" ]]; then
    ln -s "$ORIGINAL_CARGO_HOME/$directory" "$ISOLATED_CARGO_HOME/$directory"
  fi
done
for file in config config.toml credentials credentials.toml; do
  if [[ -f "$ORIGINAL_CARGO_HOME/$file" ]]; then
    cp "$ORIGINAL_CARGO_HOME/$file" "$ISOLATED_CARGO_HOME/$file"
  fi
done

echo "Checking Cargo dependency cooldown in $WORKSPACE"
set +e
(
  cd "$WORKSPACE"
  export CARGO_REGISTRY_GLOBAL_MIN_PUBLISH_AGE="${COOLDOWN_DAYS} days"
  export CARGO_HOME="$ISOLATED_CARGO_HOME"
  export COOLDOWN_INCOMPATIBLE_PUBLISH_AGE=deny
  export COOLDOWN_LOCKFILE_BASELINE=ignore
  export RUSTC_WRAPPER=""
  "$VERIFIER" cooldown --workspace --all-features tree --locked --depth 0 >/dev/null
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
