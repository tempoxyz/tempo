#!/usr/bin/env bash
#
# Patches a Foundry checkout to resolve tempo-* crates from a local Tempo
# checkout instead of git/crates-io. Used by both GitHub Actions (specs.yml)
# and the Argo invariant-tests workflow.
#
# Usage:
#   scripts/foundry-patch.sh <tempo_root> <foundry_root>
#
# Example (GHA – repos side-by-side):
#   scripts/foundry-patch.sh "$GITHUB_WORKSPACE/tempo" "$GITHUB_WORKSPACE/foundry"
#
# Example (Argo – /workspace layout):
#   /workspace/scripts/foundry-patch.sh /workspace /workspace/foundry

set -euo pipefail

TEMPO_ROOT="${1:?Usage: $0 <tempo_root> <foundry_root>}"
FOUNDRY_ROOT="${2:?Usage: $0 <tempo_root> <foundry_root>}"

TEMPO_CARGO="$TEMPO_ROOT/Cargo.toml"
FOUNDRY_CARGO="$FOUNDRY_ROOT/Cargo.toml"

if [[ ! -f "$TEMPO_CARGO" ]]; then
  echo "ERROR: Tempo Cargo.toml not found at $TEMPO_CARGO" >&2
  exit 1
fi
if [[ ! -f "$FOUNDRY_CARGO" ]]; then
  echo "ERROR: Foundry Cargo.toml not found at $FOUNDRY_CARGO" >&2
  exit 1
fi

# Already patched – nothing to do
if grep -q '^\[patch\."https://github.com/tempoxyz/tempo"\]' "$FOUNDRY_CARGO"; then
  echo "Foundry Cargo.toml already contains tempo git patch section – skipping."
  exit 0
fi

# ── 1. Discover tempo-* workspace crates that have local paths ──────────────
PATCHES="$({
  awk '
    /^\[workspace.dependencies\]/ { in_section = 1; next }
    in_section && /^\[/ { exit }
    in_section && $1 ~ /^tempo-/ && index($0, "path = \"") {
      split($0, path_parts, /path = "/)
      split(path_parts[2], rest, /"/)
      print $1 "\t" rest[1]
    }
  ' "$TEMPO_CARGO" | sort
})"

if [[ -z "$PATCHES" ]]; then
  echo "ERROR: No path-based tempo-* workspace dependencies found in $TEMPO_CARGO" >&2
  exit 1
fi

# ── 2. Patch [patch."https://github.com/tempoxyz/tempo"] ────────────────────
{
  printf '\n[patch."https://github.com/tempoxyz/tempo"]\n'
  while IFS=$'\t' read -r crate path; do
    [[ -n "$crate" ]] || continue
    printf '%s = { path = "%s/%s" }\n' "$crate" "$TEMPO_ROOT" "$path"
  done <<< "$PATCHES"
} >> "$FOUNDRY_CARGO"

# ── 3. Patch [patch.crates-io] ──────────────────────────────────────────────
# Upstream foundry pins some tempo crates to git revisions in [patch.crates-io].
# Replace those with local paths so Cargo doesn't conflict.
while IFS=$'\t' read -r crate path; do
  [[ -n "$crate" ]] || continue
  local_path="${TEMPO_ROOT}/${path}"
  replacement="${crate} = { path = \"${local_path}\" }"
  tmp_cargo="$(mktemp "${FOUNDRY_CARGO}.XXXXXX")"
  awk -v crate="$crate" -v replacement="$replacement" '
    /^\[patch\.crates-io\]/ {
      seen = 1
      in_section = 1
      print
      next
    }
    in_section && /^\[/ {
      if (!done) {
        print replacement
        done = 1
      }
      in_section = 0
    }
    in_section && index($0, crate " = ") == 1 {
      if (!done) {
        print replacement
        done = 1
      }
      next
    }
    { print }
    END {
      if (!seen) {
        print ""
        print "[patch.crates-io]"
        print replacement
      } else if (in_section && !done) {
        print replacement
      }
    }
  ' "$FOUNDRY_CARGO" > "$tmp_cargo"
  mv "$tmp_cargo" "$FOUNDRY_CARGO"
done <<< "$PATCHES"

echo "Updated Cargo.toml patch sections:"
sed -n '/^\[patch\./,$p' "$FOUNDRY_CARGO"

# ── 4. Re-resolve the lockfile without upgrading unrelated crates ──────────
# `cargo update` can pull newer upstream deps from Foundry's workspace, which is non-deterministic.
# A normal resolver pass is enough to rewrite the lockfile entries for the tempo path overrides.
# Keep this aligned with the CI Forge build so Optimism-only dependencies do not re-enter resolution.
#
# When tempo's reth bump introduces a stricter constraint on a transitive crate
# already pinned in foundry's lockfile (e.g. reth bumps `alloy-eip7928` to ^0.3.6
# while foundry's lock has 0.3.5), cargo cannot resolve it without an update.
# On such failures, parse the conflicting package out of the error and run a
# targeted `cargo update -p <pkg>` for it, then retry. If Cargo reports the
# previously selected version, include it to avoid ambiguity when Foundry's
# lockfile contains multiple versions of the same package. Loop while there are
# pending conflicts so several distinct crates can be resolved in one run
# without falling back to a blanket `cargo update`. Bail out if the same crate
# conflicts twice in a row (i.e. `cargo update` made no progress).
pushd "$FOUNDRY_ROOT" >/dev/null
prev_conflict_pkg=""
while true; do
  err="$(cargo metadata --format-version=1 --no-default-features 2>&1 >/dev/null)" && break
  clean_err="$(printf '%s\n' "$err" | sed -E 's/\x1b\[[0-9;]*[[:alpha:]]//g')"
  conflict_pkg="$(printf '%s\n' "$clean_err" | sed -nE 's/^error: failed to select a version for `([^`]+)`.*/\1/p' | head -n1)"
  selected_version="$(printf '%s\n' "$clean_err" | sed -nE 's/^[[:space:]]*previously selected package `[^ ]+ v([^`]+)`.*/\1/p' | head -n1)"
  if [[ -z "$conflict_pkg" || "$conflict_pkg" == "$prev_conflict_pkg" ]]; then
    printf '%s\n' "$clean_err" >&2
    exit 1
  fi
  update_pkg="$conflict_pkg"
  if [[ -n "$selected_version" ]]; then
    update_pkg="${conflict_pkg}@${selected_version}"
  fi
  echo "cargo metadata failed on '$conflict_pkg' constraint; running 'cargo update -p $update_pkg' and retrying"
  cargo update -p "$update_pkg" >/dev/null
  prev_conflict_pkg="$conflict_pkg"
done

stale_tempo_pkgs="$(
  awk '
    /^\[\[package\]\]/ {
      name = ""
      version = ""
      next
    }
    /^name = / {
      name = $3
      gsub(/"/, "", name)
      next
    }
    /^version = / {
      version = $3
      gsub(/"/, "", version)
      next
    }
    /^source = "git\+https:\/\/github.com\/tempoxyz\/tempo\?rev=/ {
      if (name != "" && version != "") {
        print name "@" version
      }
    }
  ' Cargo.lock | sort -u
)"
if [[ -n "$stale_tempo_pkgs" ]]; then
  update_args=()
  while IFS= read -r pkg; do
    [[ -n "$pkg" ]] || continue
    update_args+=("-p" "$pkg")
  done <<< "$stale_tempo_pkgs"
  echo "Cargo.lock still contains stale Tempo git packages; running 'cargo update ${update_args[*]}'"
  cargo update "${update_args[@]}" >/dev/null
  cargo metadata --format-version=1 --no-default-features >/dev/null
fi
popd >/dev/null

if grep -q '^source = "git+https://github.com/tempoxyz/tempo?rev=' "$FOUNDRY_ROOT/Cargo.lock"; then
  echo "ERROR: Tempo git sources still present in Cargo.lock after patching:" >&2
  grep '^source = "git+https://github.com/tempoxyz/tempo?rev=' "$FOUNDRY_ROOT/Cargo.lock" >&2
  echo "Expected all Tempo crates to resolve locally after patching" >&2
  exit 1
fi

echo "Foundry patched successfully – all tempo crates resolve from $TEMPO_ROOT"
