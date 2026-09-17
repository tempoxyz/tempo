#!/usr/bin/env bash
set -euo pipefail

trial_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
tempo_dir=$(cd -- "$trial_dir/../.." && pwd)
: "${PARALEGAL_BIN_DIR:?Set PARALEGAL_BIN_DIR to the pinned Paralegal target/debug or install bin directory}"
export PATH="$PARALEGAL_BIN_DIR:$PATH"
cd "$tempo_dir"

strict_args=(--strict)
trial_mode=strict
case "${1:-}" in
  "") ;;
  --diagnostic)
    strict_args=()
    trial_mode=diagnostic
    echo 'DIAGNOSTIC ONLY: upstream may silently omit unsupported constants.' >&2
    ;;
  *) echo 'Usage: analyze.sh [--diagnostic]' >&2; exit 2 ;;
esac

# Upstream omits strictness and entrypoint flags from its Cargo cache key.
# result_path is hashed, so bind it to the mode and this runner's full contents.
trial_config_hash=$(sha256sum "${BASH_SOURCE[0]}" | cut -d ' ' -f 1)
mkdir -p "$trial_dir/target"
trial_graph="$trial_dir/target/tempo-$trial_mode-$trial_config_hash.o"

# Upstream cargo_metadata 0.14 only accepts numeric debuginfo in Cargo JSON.
# Tempo's line-tables-only profile otherwise yields an empty artifact manifest.
cargo paralegal-flow --target tempo-precompiles --include crate "${strict_args[@]}" \
  --result-path "$trial_graph" \
  --external-annotations "$trial_dir/markers.toml" \
  --analyze tempo_precompiles::tip20::TIP20Token::grant_role \
  --analyze tempo_precompiles::tip20::TIP20Token::revoke_role \
  --analyze tempo_precompiles::tip20::TIP20Token::renounce_role \
  --analyze tempo_precompiles::tip20::TIP20Token::set_role_admin \
  --analyze tempo_precompiles::tip20::TIP20Token::transfer \
  --analyze tempo_precompiles::tip20::TIP20Token::transfer_from \
  --analyze tempo_precompiles::tip20::TIP20Token::transfer_with_memo \
  --analyze tempo_precompiles::tip20::TIP20Token::transfer_from_with_memo \
  -- --locked -p tempo-precompiles --lib --no-default-features --jobs 4 \
  --config profile.dev.debug=0

cargo +nightly-2026-04-20 run --locked --manifest-path "$trial_dir/Cargo.toml" -- "$tempo_dir/paralegal-artifact.json"
