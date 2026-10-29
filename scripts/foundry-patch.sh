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
TEMPO_LOCK="$TEMPO_ROOT/Cargo.lock"
FOUNDRY_CARGO="$FOUNDRY_ROOT/Cargo.toml"
FOUNDRY_LOCK="$FOUNDRY_ROOT/Cargo.lock"

if [[ ! -f "$TEMPO_CARGO" ]]; then
  echo "ERROR: Tempo Cargo.toml not found at $TEMPO_CARGO" >&2
  exit 1
fi
if [[ ! -f "$TEMPO_LOCK" ]]; then
  echo "ERROR: Tempo Cargo.lock not found at $TEMPO_LOCK" >&2
  exit 1
fi
if [[ ! -f "$FOUNDRY_CARGO" ]]; then
  echo "ERROR: Foundry Cargo.toml not found at $FOUNDRY_CARGO" >&2
  exit 1
fi
if [[ ! -f "$FOUNDRY_LOCK" ]]; then
  echo "ERROR: Foundry Cargo.lock not found at $FOUNDRY_LOCK" >&2
  exit 1
fi

has_tempo_git_patch=false
if grep -q '^\[patch\."https://github.com/tempoxyz/tempo"\]' "$FOUNDRY_CARGO"; then
  has_tempo_git_patch=true
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

# ── 2. Replace Foundry's direct Tempo git dependencies ──────────────────────
# [patch] entries do not always dislodge old git-sourced lockfile packages when
# the local checkout has a different crate version. Rewrite Foundry's direct
# tempo-* dependencies (including `package = "tempo-*"` aliases) to local
# paths first, preserving any feature flags. Foundry may take these from
# tempoxyz/tempo or from a fork.
patches_file="$(mktemp)"
printf '%s\n' "$PATCHES" > "$patches_file"
tmp_cargo="$(mktemp "${FOUNDRY_CARGO}.XXXXXX")"
awk -v root="$TEMPO_ROOT" -v patches_file="$patches_file" '
  BEGIN {
    while ((getline line < patches_file) > 0) {
      split(line, parts, "\t")
      if (parts[1] != "") paths[parts[1]] = root "/" parts[2]
    }
  }
  /^[A-Za-z0-9_-]+ = \{/ && /git = "https:\/\/github.com\/(tempoxyz|mablr)\/tempo"/ {
    crate = $1
    if (match($0, /package = "[^"]+"/)) {
      crate = substr($0, RSTART + 11, RLENGTH - 12)
    }
    if (crate in paths) {
      sub(/\{[[:space:]]*/, "{ path = \"" paths[crate] "\", ")
      gsub(/[[:space:]]*git = "https:\/\/github.com\/(tempoxyz|mablr)\/tempo",[[:space:]]*/, "")
      gsub(/[[:space:]]*rev = "[^"]+",?[[:space:]]*/, "")
      gsub(/,[[:space:]]*}/, " }")
    }
  }
  { print }
' "$FOUNDRY_CARGO" > "$tmp_cargo"
mv "$tmp_cargo" "$FOUNDRY_CARGO"
rm -f "$patches_file"

# ── 3. Patch [patch."https://github.com/tempoxyz/tempo"] ────────────────────
if [[ "$has_tempo_git_patch" == "true" ]]; then
  echo "Foundry Cargo.toml already contains tempo git patch section – keeping existing section."
else
  {
    printf '\n[patch."https://github.com/tempoxyz/tempo"]\n'
    while IFS=$'\t' read -r crate path; do
      [[ -n "$crate" ]] || continue
      printf '%s = { path = "%s/%s" }\n' "$crate" "$TEMPO_ROOT" "$path"
    done <<< "$PATCHES"
  } >> "$FOUNDRY_CARGO"
fi

# ── 4. Patch [patch.crates-io] ──────────────────────────────────────────────
# Upstream foundry pins some tempo crates to git revisions in [patch.crates-io].
# Replace those with local paths so Cargo doesn't conflict. Tempo's own git
# patches for other crates (e.g. reth-core) only apply inside the Tempo
# workspace, so carry them over too.
CRATES_IO_PATCHES="$({
  while IFS=$'\t' read -r crate path; do
    [[ -n "$crate" ]] || continue
    printf '%s\t%s = { path = "%s/%s" }\n' "$crate" "$crate" "$TEMPO_ROOT" "$path"
  done <<< "$PATCHES"
  awk '
    /^\[patch\.crates-io\]/ { in_section = 1; next }
    in_section && /^\[/ { exit }
    in_section && $1 !~ /^tempo-/ && /^[A-Za-z0-9_-]+ = \{ git = / { print $1 "\t" $0 }
  ' "$TEMPO_CARGO"
})"

while IFS=$'\t' read -r crate replacement; do
  [[ -n "$crate" ]] || continue
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
done <<< "$CRATES_IO_PATCHES"

# ── 5. Patch evm2 ────────────────────────────────────────────────────────────
# Tempo's reth crates resolve evm2 through the alloy-rs/evm2 git patch declared
# in Tempo's root Cargo.toml. Foundry may depend on a fork of evm2 directly, so
# apply the same patch to every evm2 source in the graph to keep a single evm2.
EVM2_PATCH_URL="https://github.com/alloy-rs/evm2"
EVM2_PATCHES="$(awk -v url="[patch.\"$EVM2_PATCH_URL\"]" '
  $0 == url { in_section = 1; next }
  in_section && /^\[/ { exit }
  in_section && /^evm2[A-Za-z0-9_-]* = \{ git = / { print }
' "$TEMPO_CARGO")"

if [[ -n "$EVM2_PATCHES" ]]; then
  evm2_sources=("$EVM2_PATCH_URL")
  if grep -Eq '^evm2[A-Za-z0-9_-]* = \{.*git = "https://github.com/mablr/evm2"' "$FOUNDRY_CARGO"; then
    evm2_sources+=("https://github.com/mablr/evm2")
  fi
  for source in "${evm2_sources[@]}"; do
    if grep -qF "[patch.\"$source\"]" "$FOUNDRY_CARGO"; then
      echo "Foundry Cargo.toml already patches $source – keeping existing section."
      continue
    fi
    printf '\n[patch."%s"]\n%s\n' "$source" "$EVM2_PATCHES" >> "$FOUNDRY_CARGO"
  done
fi

echo "Updated Cargo.toml patch sections:"
sed -n '/^\[patch\./,$p' "$FOUNDRY_CARGO"

# Foundry's lockfile can still contain packages sourced from old
# tempoxyz/tempo git revisions after the Cargo.toml patches above are written.
# `cargo metadata` may fail before it can rewrite those entries if an old Tempo
# revision carries incompatible transitive constraints, so refresh only those
# stale Tempo packages first. The source#name@version form keeps the update targeted
# and unambiguous when the lockfile contains several versions or revisions of a crate.
update_stale_tempo_git_packages() {
  local stale_tempo_pkgs
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
      /^source = "git\+https:\/\/github.com\/(tempoxyz|mablr)\/tempo\?rev=/ {
        if (name != "" && version != "") {
          source = $3
          gsub(/"/, "", source)
          sub(/#.*/, "", source)
          print source "#" name "@" version
        }
      }
    ' Cargo.lock | sort -u
  )"

  if [[ -z "$stale_tempo_pkgs" ]]; then
    return 0
  fi

  local update_args=()
  while IFS= read -r pkg; do
    [[ -n "$pkg" ]] || continue
    update_args+=("-p" "$pkg")
  done <<< "$stale_tempo_pkgs"

  echo "Cargo.lock still contains stale Tempo git packages; running 'cargo update ${update_args[*]}'"
  cargo update "${update_args[@]}" >/dev/null
}

locked_versions() {
  local lockfile="$1"
  local package="$2"
  awk -v package="$package" '
    /^\[\[package\]\]$/ { selected = 0; next }
    /^name = / {
      name = $3
      gsub(/"/, "", name)
      selected = name == package
      next
    }
    selected && /^version = / {
      version = $3
      gsub(/"/, "", version)
      print version
    }
  ' "$lockfile" | sort -u
}

assert_lock_versions_match() {
  local package="$1"
  local tempo_versions
  local foundry_versions
  tempo_versions="$(locked_versions "$TEMPO_LOCK" "$package")"
  foundry_versions="$(locked_versions "$FOUNDRY_LOCK" "$package")"

  if [[ -z "$tempo_versions" || -z "$foundry_versions" ]]; then
    echo "ERROR: Missing $package from a lockfile (Tempo='$tempo_versions', Foundry='$foundry_versions')" >&2
    exit 1
  fi
  if [[ "$tempo_versions" != "$foundry_versions" ]]; then
    echo "ERROR: $package lock mismatch (Tempo='$tempo_versions', Foundry='$foundry_versions')" >&2
    exit 1
  fi
  echo "$package lock aligned at $tempo_versions"
}

# ── 6. Re-resolve the lockfile without upgrading unrelated crates ──────────
# `cargo update` can pull newer upstream deps from Foundry's workspace, which is non-deterministic.
# A workspace-only `cargo update` re-resolves the lockfile for the tempo path overrides without
# downloading crates, so a blocked or unrelated Foundry dependency cannot fail the resolver check.
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
update_stale_tempo_git_packages
prev_conflict_pkg=""
while true; do
  err="$(cargo update --workspace 2>&1 >/dev/null)" && break
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
  echo "cargo update --workspace failed on '$conflict_pkg' constraint; running 'cargo update -p $update_pkg' and retrying"
  cargo update -p "$update_pkg" >/dev/null
  prev_conflict_pkg="$conflict_pkg"
done

update_stale_tempo_git_packages
cargo update --workspace >/dev/null
for package in alloy-primitives alloy-sol-types evm2; do
  assert_lock_versions_match "$package"
done
# Version equality cannot tell two evm2 sources apart; a split graph has two entries.
evm2_entries="$(grep -c '^name = "evm2"$' Cargo.lock || true)"
if [[ "$evm2_entries" != "1" ]]; then
  echo "ERROR: expected exactly one evm2 package in Foundry's Cargo.lock, found $evm2_entries" >&2
  exit 1
fi
popd >/dev/null

if grep -Eq '^source = "git\+https://github.com/(tempoxyz|mablr)/tempo\?rev=' "$FOUNDRY_ROOT/Cargo.lock"; then
  echo "ERROR: Tempo git sources still present in Cargo.lock after patching:" >&2
  grep -E '^source = "git\+https://github.com/(tempoxyz|mablr)/tempo\?rev=' "$FOUNDRY_ROOT/Cargo.lock" >&2
  echo "Expected all Tempo crates to resolve locally after patching" >&2
  exit 1
fi

echo "Foundry patched successfully – all tempo crates resolve from $TEMPO_ROOT"
