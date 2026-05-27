#!/usr/bin/env bash
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

run() {
  echo "+ $*"
  "$@"
}

run cargo fmt --all -- --check
run test -s docs/blockstm-builder-implementation-plan.md
run rg -n "sender nonce|expiring nonce|fee payer|validator fee|keychain|TIP-20|AMM|order book|state-aware" docs/blockstm-builder-implementation-plan.md
run rg -n "ExpiringNonceUse|Tip20FeeEscrowDelta|Tip20TransferDelta|CollectedFeesDelta|SemanticPrefixRead|pure TIP20 benchmark|25000|1.5x" docs/blockstm-builder-implementation-plan.md
run cargo test --workspace blockstm_core_ -- --nocapture
run cargo test --workspace blockstm_concurrent_ -- --nocapture
run cargo test --workspace blockstm_overlay_ -- --nocapture
run cargo test --workspace blockstm_mv_memory_ -- --nocapture
run cargo test --workspace blockstm_rw_ -- --nocapture
run cargo test --workspace blockstm_dependency_ -- --nocapture
run cargo test --workspace blockstm_conflict_policy_ -- --nocapture
run cargo test --workspace blockstm_result_reuse_ -- --nocapture
run cargo test --workspace blockstm_action_ -- --nocapture
run cargo test --workspace blockstm_direct_slot_ -- --nocapture
run cargo test --workspace blockstm_executor_ -- --nocapture
run cargo test --workspace blockstm_builder_ -- --nocapture
run cargo test --workspace blockstm_config_ -- --nocapture
run cargo test --workspace blockstm_metrics_ -- --nocapture
run cargo test --workspace blockstm_randomized_ -- --nocapture
run cargo build --workspace --bins
run cargo test --workspace blockstm_node_e2e_starts_with_flag_and_builds_serial_equivalent_block -- --ignored --nocapture

baseline_log="$(mktemp /tmp/tempo-tip20-baseline.XXXXXX.log)"
run cargo bench --profile profiling -p tempo-evm --bench tip20_execution txgen_tip20_pure_execution -- --noplot 2>&1 | tee "$baseline_log"
baseline_tps="$(python3 - "$baseline_log" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
matches = re.findall(r"thrpt:\s+\[\s*([0-9.]+)\s+([KMG]?elem/s)\s+([0-9.]+)\s+([KMG]?elem/s)\s+([0-9.]+)\s+([KMG]?elem/s)\s*\]", text)
if not matches:
    raise SystemExit("failed to parse existing TIP20 Criterion throughput")

value, unit = matches[-1][2], matches[-1][3]
scale = {"elem/s": 1.0, "Kelem/s": 1_000.0, "Melem/s": 1_000_000.0, "Gelem/s": 1_000_000_000.0}[unit]
print(float(value) * scale)
PY
)"
echo "existing TIP20 median baseline: ${baseline_tps} tx/s"
TEMPO_EXISTING_TIP20_BASELINE_TPS="$baseline_tps" \
  run cargo bench --profile profiling -p tempo-payload-builder --bench blockstm_tip20_builder -- --noplot

blockstm_log="$(mktemp /tmp/tempo-blockstm-repeated.XXXXXX.log)"
run cargo bench --profile profiling -p tempo-payload-builder --bench blockstm_tip20_builder_repeated -- --noplot 2>&1 | tee "$blockstm_log"
blockstm_tps="$(python3 - "$blockstm_log" <<'PY'
import re
import sys

text = open(sys.argv[1], encoding="utf-8").read()
matches = re.findall(r"thrpt:\s+\[\s*([0-9.]+)\s+([KMG]?elem/s)\s+([0-9.]+)\s+([KMG]?elem/s)\s+([0-9.]+)\s+([KMG]?elem/s)\s*\]", text)
if not matches:
    raise SystemExit("failed to parse repeated Block-STM Criterion throughput")

value, unit = matches[-1][2], matches[-1][3]
scale = {"elem/s": 1.0, "Kelem/s": 1_000.0, "Melem/s": 1_000_000.0, "Gelem/s": 1_000_000_000.0}[unit]
print(float(value) * scale)
PY
)"
echo "repeated Block-STM median: ${blockstm_tps} tx/s"
python3 - "$blockstm_tps" "$baseline_tps" <<'PY'
import sys

blockstm_tps = float(sys.argv[1])
baseline_tps = float(sys.argv[2])
if blockstm_tps < 500_000.0:
    raise SystemExit(f"repeated Block-STM TPS {blockstm_tps:.2f} is below 500k")
if blockstm_tps < baseline_tps * 2.0:
    raise SystemExit(
        f"repeated Block-STM TPS {blockstm_tps:.2f} is below 2x existing pure TIP20 baseline {baseline_tps:.2f}"
    )
PY
