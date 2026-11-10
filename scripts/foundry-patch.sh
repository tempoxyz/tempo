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
# Tempo's reth crates and Foundry must share one evm2, and Foundry may depend on
# a fork or another revision of it. Redirect every evm2 source in the graph to
# Tempo's pinned revision. The redirect goes through evm2's pre-transfer URL,
# which Cargo treats as another source, because it rejects a patch from the same
# source.
EVM2_PATCH_URL="https://github.com/alloy-rs/evm2"
EVM2_REV="$(sed -nE 's/^evm2 = \{.*rev = "([0-9a-f]+)".*/\1/p' "$TEMPO_CARGO" | head -n1)"
EVM2_PATCHES=""
if [[ -n "$EVM2_REV" ]]; then
  for crate in evm2 evm2-inspectors evm2-jit evm2-macros; do
    EVM2_PATCHES+="$crate = { git = \"https://github.com/DaniPopes/evm2\", rev = \"$EVM2_REV\" }"$'\n'
  done
fi

if [[ -n "$EVM2_PATCHES" ]]; then
  evm2_sources=("$EVM2_PATCH_URL")
  if grep -Eq '^evm2[A-Za-z0-9_-]* = \{.*git = "https://github.com/mablr/evm2"' "$FOUNDRY_CARGO"; then
    evm2_sources+=("https://github.com/mablr/evm2")
  fi
  for source in "${evm2_sources[@]}"; do
    tmp_cargo="$(mktemp "${FOUNDRY_CARGO}.XXXXXX")"
    awk -v section="[patch.\"$source\"]" -v patches="$EVM2_PATCHES" '
      $0 == section {
        seen = 1
        in_section = 1
        print
        printf "%s", patches
        next
      }
      /^\[/ { in_section = 0 }
      in_section && /^evm2[A-Za-z0-9_-]* = / { next }
      { print }
      END {
        if (!seen) {
          print ""
          print section
          printf "%s", patches
        }
      }
    ' "$FOUNDRY_CARGO" > "$tmp_cargo"
    mv "$tmp_cargo" "$FOUNDRY_CARGO"
  done
fi

# Message inputs may reference caller memory and must be resolved through the EVM.
# Celo's transfer also mutably borrows the EVM, so preserve its input first.
if [[ -f "$FOUNDRY_ROOT/crates/evm/core/src/evm/eth.rs" ]]; then
  sed -i \
    -e 's/return self.celo.then(|| celo_transfer(evm, \&message.input, gas));/return self.celo.then(|| {\n                let input = evm.message_input(message).to_vec();\n                celo_transfer(evm, \&input, gas)\n            });/' \
    -e 's/\&message.input/evm.message_input(message)/g' \
    "$FOUNDRY_ROOT/crates/evm/core/src/evm/eth.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/coverage/src/inspector.rs" ]]; then
  sed -i 's/CallData::new(\&message.input)/CallData::new(interp.input())/' \
    "$FOUNDRY_ROOT/crates/evm/coverage/src/inspector.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/fuzz/src/inspector.rs" ]]; then
  sed -i 's/message.input.to_bytes()/message.input.to_bytes(interp.memory())/g' \
    "$FOUNDRY_ROOT/crates/evm/fuzz/src/inspector.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/logs.rs" ]] &&
  grep -q 'self.hardhat_log(&message.input)' "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/logs.rs"; then
  sed -i \
    -e '/fn do_hardhat_log<T: EvmTypesHost>(/,/) -> Option<MessageResult<T>>/s/        message: \&Message<T>,/        interp: \&mut Interpreter<\x27_, \x27_, T>,\n        message: \&Message<T>,/' \
    -e 's/self.hardhat_log(\&message.input)/self.hardhat_log(message.input.as_bytes(interp.memory()))/' \
    -e 's/        _interp: \&mut Interpreter/        interp: \&mut Interpreter/' \
    -e 's/self.do_hardhat_log::<T>(message)/self.do_hardhat_log::<T>(interp, message)/' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/logs.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs" ]]; then
  if grep -q 'input.extend_from_slice(&message.input);' "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"; then
    sed -i \
      -e '/let create2_deployer = self.inner.create2_deployer;/a\        let init_code = message.input.to_bytes(interp.memory());' \
      -e 's/input.extend_from_slice(\&message.input)/input.extend_from_slice(\&init_code)/' \
      "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"
  fi
  sed -i \
    -e 's/message.input.to_bytes()/Bytes::copy_from_slice(evm.message_input(message))/g' \
    -e 's/\.get(\&\*message.input)/.get(interp.host().message_input(message))/' \
    -e 's/message.input.get(\.\.4)/interp.host().message_input(message).get(..4)/g' \
    -e 's/if interp.host().message_input(message).get(\.\.4)/if evm.message_input(message).get(..4)/' \
    -e 's/cheatcodes.is_storage_hook_callback(message)/cheatcodes.is_storage_hook_callback(message, message.input.as_bytes(interp.memory()))/' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/cheatcodes/src/inspector.rs" ]]; then
  sed -i \
    -e '/message.destination = derive_create_destination(/,/    );/s/\&message.input/ccx.evm.message_input(\&message)/' \
    -e 's/Vm::VmCalls::abi_decode(\&message.input)/Vm::VmCalls::abi_decode(interp.host().message_input(message))/' \
    -e 's/\&call.input,/call.input.as_bytes(interp.memory()),/g' \
    -e 's/call.input.to_bytes()/call.input.to_bytes(interp.memory())/g' \
    -e 's/with_input(call.input.to_bytes(interp.memory()))/with_input(Bytes::copy_from_slice(evm.message_input(call)))/' \
    -e 's/input.input.to_bytes()/input.input.to_bytes(interp.memory())/g' \
    -e 's/\&input.input,/input.input.as_bytes(interp.memory()),/g' \
    -e 's/is_storage_hook_callback(\&self, call: \&MessageFor<FEN>)/is_storage_hook_callback(\&self, call: \&MessageFor<FEN>, input: \&[u8])/' \
    -e 's/\*call.input == \*active.callback_input/input == active.callback_input.as_ref()/' \
    -e 's/self.is_storage_hook_callback(call)/self.is_storage_hook_callback(call, call.input.as_bytes(interp.memory()))/' \
    "$FOUNDRY_ROOT/crates/cheatcodes/src/inspector.rs"
fi

# evm2's mark_created now preserves the storage baseline by default.
if [[ -f "$FOUNDRY_ROOT/crates/evm/core/src/evm/lifecycle.rs" ]]; then
  sed -i 's/\.mark_created_keeping_storage()/\.mark_created()/g' \
    "$FOUNDRY_ROOT/crates/evm/core/src/evm/lifecycle.rs"
fi

# Initial call depth belongs to the EVM, not its execution configuration.
if [[ -f "$FOUNDRY_ROOT/crates/evm/core/src/backend/mod.rs" ]] &&
  grep -q 'env.version.initial_call_depth' "$FOUNDRY_ROOT/crates/evm/core/src/backend/mod.rs"; then
  sed -i \
    -e '/env.version.initial_call_depth = depth;/d' \
    -e '/prepared.set_access_list(target.transaction.access_list().cloned());/i\        prepared.set_initial_call_depth(depth);' \
    "$FOUNDRY_ROOT/crates/evm/core/src/backend/mod.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/core/src/evm/lifecycle.rs" ]] &&
  ! grep -q 'pub fn set_initial_call_depth' "$FOUNDRY_ROOT/crates/evm/core/src/evm/lifecycle.rs"; then
  sed -i '/    \/\/\/ Records the transaction.s EIP-2930 access list\./i\    /// Sets the inspector-visible depth of the nested transaction\x27s root message.\n    pub fn set_initial_call_depth(\&mut self, depth: u16) {\n        self.executor.set_initial_call_depth(depth);\n    }\n' \
    "$FOUNDRY_ROOT/crates/evm/core/src/evm/lifecycle.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs" ]] &&
  grep -q 'env.version.initial_call_depth' "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"; then
  sed -i \
    -e 's/let mut env = env.unwrap_or_else(|| evm_env(evm));/let env = env.unwrap_or_else(|| evm_env(evm));/' \
    -e '/env.version.initial_call_depth = depth;/d' \
    -e '/let mut child = backend.backend().lifecycle().nested_evm(evm, tx, Some(env), None);/a\        child.set_initial_call_depth(depth);' \
    -e '/env.version.initial_call_depth = depth + 1;/d' \
    -e 's/let (prepared, mut replay) = backend.backend().prepare_nested(tx.clone(), evm, Some(env));/let (mut prepared, mut replay) =\n            backend.backend().prepare_nested(tx.clone(), evm, Some(env));\n        prepared.set_initial_call_depth(depth + 1);/' \
    -e '/The root keeps its depth in the surrounding trace, with a fresh call-depth budget\./d' \
    -e '/env.version.initial_call_depth = message.depth;/d' \
    -e '/let mut child = backend.backend().lifecycle().nested_evm(evm, \&tx, Some(env), None);/a\        // The root keeps its depth in the surrounding trace, with a fresh call-depth budget.\n        child.set_initial_call_depth(message.depth);' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/cheatcodes/src/inspector.rs" ]]; then
  sed -i 's/interp.version().initial_call_depth/interp.host().initial_call_depth()/g' \
    "$FOUNDRY_ROOT/crates/cheatcodes/src/inspector.rs"
fi

# Keep the exhaustive execution-config comparison aligned with Version's fields.
if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/executors/mod.rs" ]]; then
  sed -i \
    -e 's/^        initial_call_depth,$/        tx_total_gas_cap,/' \
    -e 's/version.initial_call_depth == initial_call_depth/version.tx_total_gas_cap == tx_total_gas_cap/' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/executors/mod.rs"
fi

# Tracing now uses evm2's OpcodeSet instead of the inspectors' OpcodeFilter.
# The precompile flag still controls tagging for exclusion, not call recording.
if [[ -f "$FOUNDRY_ROOT/crates/evm/traces/src/lib.rs" ]]; then
  sed -i \
    -e 's/use evm2_inspectors::{ColorChoice, tracing::OpcodeFilter};/use evm2_inspectors::ColorChoice;/' \
    -e 's/OpcodeFilter::new().enabled(OpCode::JUMP).enabled(OpCode::JUMPDEST)/[OpCode::JUMP.get(), OpCode::JUMPDEST.get()].into_iter().collect()/' \
    -e 's/exclude_precompile_calls: false/record_precompile_calls: false/' \
    "$FOUNDRY_ROOT/crates/evm/traces/src/lib.rs"
fi

# The removed Host helper delegated to the account's gas-emptiness predicate.
if [[ -f "$FOUNDRY_ROOT/crates/cheatcodes/src/fs.rs" ]]; then
  sed -i \
    's/ccx.evm.target_is_empty_for_new_account_gas(\&created_address, version.features)?/ccx.evm.state_mut().account(\&created_address)?.is_empty_for_new_account_gas(version.features)/' \
    "$FOUNDRY_ROOT/crates/cheatcodes/src/fs.rs"
fi

if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs" ]]; then
  sed -i \
    -e 's/\.mark_created_keeping_storage()/\.mark_created()/g' \
    -e 's/inspector_config().steps\([;)]\)/inspector_config().steps()\1/g' \
    -e 's/\.target_is_empty_for_new_account_gas(\&message.destination, features)/.state_mut().account(\&message.destination).map(|account| account.is_empty_for_new_account_gas(features))/' \
    -e 's/(0\.\.=u8::MAX).filter(|\&op| filter.is_enabled(OpCode::new_or_unknown(op))).collect()/*filter/' \
    -e 's/, opcode::OpCode//' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/stack.rs"
fi

# The interpreter no longer tracks step costs; match the tracer's gas accounting.
if [[ -f "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/debug_recorder.rs" ]] &&
  grep -q 'interp.step_cost()' "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/debug_recorder.rs"; then
  sed -i \
    -e 's/^    gas: u64,$/    gas: u64,\n    gas_before: u64,/' \
    -e 's/^            gas,$/            gas,\n            gas_before: interp.gas().remaining_excluding_state_spill(),/' \
    -e 's/interp.step_cost()/if interp.result().is_err_and(InstrStop::is_out_of_gas) {\n                step.gas\n            } else {\n                step.gas_before.saturating_sub(interp.gas().remaining_excluding_state_spill())\n            }/' \
    "$FOUNDRY_ROOT/crates/evm/evm/src/inspectors/debug_recorder.rs"
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
