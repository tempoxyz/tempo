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
# targeted `cargo update -p <pkg>` for it, then retry. Loop while there are
# pending conflicts so several distinct crates can be resolved in one run
# without falling back to a blanket `cargo update`. Bail out if the same crate
# conflicts twice in a row (i.e. `cargo update` made no progress).
pushd "$FOUNDRY_ROOT" >/dev/null
# Disable cargo color output so the error-parsing regex below isn't tripped up
# by ANSI escape codes when the workflow exports CARGO_TERM_COLOR=always.
export CARGO_TERM_COLOR=never
# Accumulate every conflicting crate into a single `cargo update -p` invocation.
# A targeted `cargo update -p X` only bumps X, so when tempo's reth bump pulls
# in a sibling crate that also needs bumping (e.g. alloy-primitives + alloy-sol-types
# are released together), updating just the first conflict surfaces the second one
# but leaves the first un-resolvable on its own. Add every newly-reported package
# to the same `cargo update` call so they're bumped atomically.
parse_conflict_pkg() {
  printf '%s\n' "$1" | sed -nE "s/^error: failed to select a version for \`([^\`]+)\`.*/\1/p" | head -n1
}
# Groups of crates that are released together and must be bumped in lock-step.
# When the resolver reports a conflict on any member, every member of the
# group is added to `cargo update -p` so they all move to the same major.minor.
# This avoids leaving e.g. alloy-dyn-abi at 1.5.7 while alloy-sol-types is
# bumped to 1.6.0, which produces winnow trait mismatches at compile time
# because alloy-sol-type-parser unifies to 1.6 (winnow 1.0) but alloy-dyn-abi
# 1.5.7's own code references winnow 0.7 types.
sibling_groups=(
  "alloy-dyn-abi alloy-sol-macro alloy-sol-macro-expander alloy-sol-macro-input alloy-sol-type-parser alloy-sol-types"
)
expand_siblings() {
  local pkg="$1"
  for group in "${sibling_groups[@]}"; do
    if [[ " $group " == *" $pkg "* ]]; then
      printf '%s\n' $group
      return
    fi
  done
  printf '%s\n' "$pkg"
}
update_pkgs=()
seen_pkgs=" "
add_pkg() {
  local pkg
  for pkg in $(expand_siblings "$1"); do
    if [[ "$seen_pkgs" != *" $pkg "* ]]; then
      update_pkgs+=("-p" "$pkg")
      seen_pkgs+="$pkg "
    fi
  done
}
while true; do
  err="$(cargo metadata --format-version=1 --no-default-features 2>&1 >/dev/null)" && break
  conflict_pkg="$(parse_conflict_pkg "$err")"
  if [[ -z "$conflict_pkg" || "$seen_pkgs" == *" $conflict_pkg "* ]]; then
    printf '%s\n' "$err" >&2
    exit 1
  fi
  add_pkg "$conflict_pkg"
  echo "cargo metadata failed on '$conflict_pkg' constraint; running 'cargo update ${update_pkgs[*]}' and retrying"
  # cargo update can itself fail when its targeted bump exposes another sibling
  # crate that also needs bumping. Parse the new conflict from the update error
  # and extend the update list until cargo update succeeds or stops making progress.
  while true; do
    upd_err="$(cargo update "${update_pkgs[@]}" 2>&1 >/dev/null)" && break
    new_pkg="$(parse_conflict_pkg "$upd_err")"
    if [[ -z "$new_pkg" || "$seen_pkgs" == *" $new_pkg "* ]]; then
      printf '%s\n' "$upd_err" >&2
      exit 1
    fi
    add_pkg "$new_pkg"
    echo "cargo update failed on '$new_pkg'; adding it to the update list and retrying"
  done
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
