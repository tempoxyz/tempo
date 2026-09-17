#!/usr/bin/env bash
set -euo pipefail

trial_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
: "${PARALEGAL_BIN_DIR:?Set PARALEGAL_BIN_DIR to the pinned Paralegal bin directory}"
export PATH="$PARALEGAL_BIN_DIR:$PATH"
checker="$trial_dir/target/debug/tempo-paralegal-trial"
cargo +nightly-2026-04-20 build --locked --manifest-path "$trial_dir/Cargo.toml"
cd "$trial_dir/fixture"

roots=(grant_role revoke_role renounce_role set_role_admin transfer transfer_from transfer_with_memo transfer_from_with_memo)
analysis_args=()
for root in "${roots[@]}"; do
  analysis_args+=(--analyze "tempo_policy_fixture::$root")
done

# A missing marker must fail even if all remaining dependencies are valid.
sed -e 's/tempo_precompiles::tip20::TIP20Token::/tempo_policy_fixture::/g' \
  -e 's/role_authorization/unrecognized_role_check/g' "$trial_dir/markers.toml" > markers.toml
cargo paralegal-flow --target tempo-policy-fixture --include crate --strict \
  --external-annotations "$PWD/markers.toml" "${analysis_args[@]}" \
  -- --locked --lib > analysis-missing-marker.log 2>&1
if "$checker" "$PWD/paralegal-artifact.json" > policy-missing-marker.log 2>&1; then
  echo 'FAIL: missing marker was accepted'; exit 1
fi
rg -q 'missing role_authorization marker' policy-missing-marker.log
echo 'PASS: missing marker rejected'
sed 's/tempo_precompiles::tip20::TIP20Token::/tempo_policy_fixture::/g' \
  "$trial_dir/markers.toml" > markers.toml
for variant in baseline ignore-role ignore-pause ignore-policy; do
  features=()
  if [[ "$variant" != baseline ]]; then
    features=(--features "$variant")
  fi
  cargo paralegal-flow --target tempo-policy-fixture --include crate --strict \
    --external-annotations "$PWD/markers.toml" "${analysis_args[@]}" \
    -- --locked --lib "${features[@]}" > "analysis-$variant.log" 2>&1
  if "$checker" "$PWD/paralegal-artifact.json" > "policy-$variant.log" 2>&1; then
    [[ "$variant" == baseline ]] || { echo "FAIL: $variant was accepted"; exit 1; }
    echo 'PASS: baseline accepted'
  else
    [[ "$variant" != baseline ]] || { cat "policy-$variant.log"; exit 1; }
    # A missing marker, parse error or crash is not a successful sensitivity test.
    rg -q 'does not control every' "policy-$variant.log"
    echo "PASS: $variant rejected by control-dependence policy"
  fi
done
