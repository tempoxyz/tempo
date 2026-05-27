# Block-STM Payload Builder Implementation Plan

This plan is based on repository discovery in this worktree. Evidence commands:

- `cargo metadata --format-version 1 > /tmp/tempo-cargo-metadata.json`
- `rg -n "TempoBlockExecutor|commit_transaction|StateAwareBestTransactions|payload builder|prewarming|PayloadBuilder|BestTransactions" crates bin src`
- `rg -n "dev.*node|--dev|http.port|authrpc|engine|payload" crates bin scripts .github`
- `rg -n "tps|duration|accounts|max-concurrent|tip20|TXGEN_ACCOUNTS|tx_count|generate" .github bench-e2e.nu tempo.nu contrib bin crates`
- `rg -n "transfer_fee_pre_tx|transfer_fee_post_tx|_transfer|increment_collected_fees|check_and_mark_expiring_nonce|EXPIRING_NONCE_SET_CAPACITY" crates`
- `rg -n "collect_fee_pre_tx|collect_fee_post_tx|execute_fee_swap|compute_amount_out|setUserToken|validator_tokens|collected_fees" crates`

## Repository Shape

- Payload builder package: `tempo-payload-builder` at `crates/payload/builder`.
- Production builder entry: `TempoPayloadBuilder::build_payload` in `crates/payload/builder/src/lib.rs`.
- Serial normal-pool execution loop: `TempoPayloadBuilder::build_payload`, the loop that reads `StateAwareBestTransactions`, calls `builder.execute_transaction_with_result_closure`, updates gas/fee/block-size accounting, and calls `StateAwareBestTransactions::on_new_result`.
- Serial oracle transaction executor: `TempoBlockExecutor::execute_transaction_without_commit` in `crates/evm/src/block.rs`.
- Serial commit/accounting oracle: `TempoBlockExecutor::commit_transaction` in `crates/evm/src/block.rs`, plus the builder-loop accounting in `crates/payload/builder/src/lib.rs`.
- State-aware pool feedback: `StateAwareBestTransactions` in `crates/transaction-pool/src/best.rs`.
- Existing payload-builder metrics: `TempoPayloadBuilderMetrics` in `crates/payload/builder/src/metrics.rs`.
- Existing prewarming fast path and storage-slot discovery helpers: `crates/payload/builder/src/prewarming.rs`.
- Node binary target: `tempo` at `bin/tempo/src/main.rs`.
- CLI/config location for new flags: `TempoNodeArgs` and `TempoPayloadBuilderBuilder` in `crates/node/src/node.rs`.
- Existing builder CLI flag: `--builder.enable-prewarming`; new flags will be `--builder.blockstm`, `--builder.blockstm-workers <N>`, and `--builder.blockstm-tip20-actions`.
- Local dev node command for the E2E gate:
  `cargo test --workspace blockstm_node_e2e_starts_with_flag_and_builds_serial_equivalent_block -- --ignored --nocapture`. The test starts the real dev-node harness with `TempoNodeArgs { builder_blockstm: true, builder_blockstm_workers: Some(4), builder_blockstm_tip20_actions: true, .. }`, enables HTTP, submits a transaction over RPC, waits for inclusion, and checks the produced block.

## Production Modules

The implementation will live in `crates/payload/builder/src/blockstm/`:

- `mod.rs`: production entry point and public type exports.
- `config.rs`: `BlockStmConfig`, defaults, CLI adapter fields.
- `executor.rs`: `BlockStmExecutor` and `ParallelTempoBlockExecutor` orchestration.
- `scheduler.rs`: `BlockStmScheduler` deterministic indexed scheduling and retry control.
- `state_view.rs`: `BlockStmStateView` and tracking DB/state helpers.
- `rw_set.rs`: `BlockStmReadSet`, `BlockStmWriteSet`, account/storage/code keys, validation.
- `overlay.rs`: committed-prefix overlay and attempt-local writes.
- `commit.rs`: ordered commit and builder accounting handoff.
- `policy.rs`: `BlockStmConflictPolicy`, dependency domains, strategies, adaptive fallback.
- `stats.rs`: `BlockStmExecutionStats`.
- `metrics.rs`: production Block-STM metrics.
- `action/mod.rs`: `BlockStmAction`, `BlockStmActionLog`, `BlockStmResource`.
- `action/resolver.rs`: `BlockStmActionResolver`.
- `action/nonce.rs`: `ExpiringNonceUse`.
- `action/tip20.rs`: `Tip20FeeEscrowDelta`, `Tip20TransferDelta`, TIP-20 balance coverage.
- `action/fee_manager.rs`: `CollectedFeesDelta`.
- `action/semantic_read.rs`: `SemanticPrefixRead`.

Lower-level hooks used by the implementation:

- EVM read/write capture: `BlockStmTrackingDb` in `crates/payload/builder/src/blockstm/state_view.rs` wraps the real EVM database and records account, storage, code, and code-hash reads from actual execution.
- EVM result mutation: `TempoTxResult::result_mut` in `crates/evm/src/block.rs` lets the ordered semantic resolver replace covered speculative writes with serial-prefix writes before `TempoBlockExecutor::commit_transaction`.
- Production semantic action capture: `capture_tip20_semantic_plan` in `crates/payload/builder/src/blockstm/action/production.rs` derives `ExpiringNonceUse`, `Tip20FeeEscrowDelta`, `Tip20TransferDelta`, `CollectedFeesDelta`, and `SemanticPrefixRead` from successful real Tempo execution results, transaction fields, and the captured real write set.
- Production ordered semantic resolver: `BlockStmSemanticState::apply_plan` in `crates/payload/builder/src/blockstm/action/production.rs` validates actions in builder transaction order and rewrites covered nonce, fee-manager, TIP-20 balance, and collected-fee writes.
- Commit cache hydration: `hydrate_blockstm_commit_cache` in `crates/payload/builder/src/lib.rs` loads accounts touched by worker-produced `TempoTxResult`s into the canonical `State` cache before serial commit, matching the account-cache precondition naturally satisfied by serial execution.

## Pure TIP20 Benchmark Confirmation

The pure TIP20 benchmark is code-derived from `contrib/bench/txgen/presets/tip20.yml` and `.github/workflows/bench.yml`:

- GitHub bench defaults include `mode=e2e`, `preset=tip20`, `duration=300`, `accounts=1000`, and `tps=20000`; users can pass `tps=50000`.
- `bench-e2e.nu` defaults `duration=300`, `accounts=1000`, and supports the txgen e2e/dev path.
- `contrib/bench/txgen/presets/tip20.yml` generates a 100% `tip20_transfer` mix.
- Each generated tx uses `type: tempo`, random sender from `${TXGEN_ACCOUNTS}`, random recipient from the same pool, `gas_limit=300000`, `max_fee_per_gas=100000000000`, `max_priority_fee_per_gas=100000000000`, fee token `0x20c0000000000000000000000000000000000000`, `expiring_nonce: true`, and `transfer(recipient, 1)` to `0x20c0000000000000000000000000000000000000`.
- `PATH_USD_ADDRESS`/`DEFAULT_FEE_TOKEN` references in `crates/precompiles/src/lib.rs`, `crates/precompiles/src/tip20_factory/mod.rs`, and transaction-pool tests confirm `0x20c0000000000000000000000000000000000000` is PathUSD/default fee token.
- At `tps=50000` and `duration=300`, txgen creates 15,000,000 transactions.
- The release performance gate is the Criterion target `crates/payload/builder/benches/blockstm_tip20_builder.rs`, defaulting to a deterministic 25000 tx batch, 1000 accounts, and the machine worker count capped at 32. It performs an exact serial-vs-Block-STM digest check before timing, then measures the build/execution path without the verification digest so it is comparable to the existing pure TIP20 Criterion benchmark. The gate now requires the full Block-STM builder path to reach at least 500000 TPS in addition to the existing 2x serial/baseline checks and the semantic 500000 TPS check. The older ignored `blockstm_pure_tip20_parallel_builder_benchmark` remains as a test harness reference for the original 1.5x debug-style gate, but it is not the completion benchmark.
- Initial re-execution threshold for the pure TIP20 fast path: `reexecutions_total <= accepted_tx_count / 20`; fallback count for the modeled TIP20 domains must be zero.
- Existing release baseline command: `cargo bench --profile profiling -p tempo-evm --bench tip20_execution txgen_tip20_pure_execution -- --noplot`.
- Current existing profiling baseline result from the final script: `tip20_execution/txgen_tip20_pure_execution` median throughput `93.183 Kelem/s` (`time: [43.775 ms 43.957 ms 44.151 ms]`, `thrpt: [92.774 Kelem/s 93.183 Kelem/s 93.569 Kelem/s]`). The final script reparses this in-run value and passes it to the Block-STM gate.
- New Block-STM release command: `cargo bench --profile profiling -p tempo-payload-builder --bench blockstm_tip20_builder -- --noplot`.
- Current Block-STM profiling release gate result from the final script: `txs=25000`, `accounts=1000`, `workers=32`, `serial_median=279.436442ms`, `parallel_median=38.6037ms`, `semantic_median=33.48604ms`, `serial_tps=89465.78`, `parallel_tps=647606.32`, `semantic_tps=746579.77`, `speedup=7.24x`, `semantic_speedup=8.34x`, parsed existing baseline `93183.00`, `accepted=25000`, `rejected=0`, `speculative=25000`, `committed=25000`, `reused_worker_results=25000`, `conflicts=0`, `reexecutions=0`, `serial_commit_reexecutions=0`, `fallback=0`, `max_in_flight=32`, `worker_lanes=32`, and `semantic_actions=125000`.
- Current Block-STM Criterion result from the final script: `blockstm_tip20_builder/blockstm` median throughput `573.57 Kelem/s` (`time: [42.912 ms 43.587 ms 44.266 ms]`, `thrpt: [564.77 Kelem/s 573.57 Kelem/s 582.59 Kelem/s]`). The semantic end-to-end Criterion target reports median throughput `652.76 Kelem/s` (`time: [37.729 ms 38.299 ms 38.880 ms]`, `thrpt: [643.00 Kelem/s 652.76 Kelem/s 662.63 Kelem/s]`).
- The pure TIP20 benchmark path now reduces captured semantic actions inside the speculative worker pass. Workers prepare stripped receipt/gas commit records after real EVM execution, so the ordered phase only fixes cumulative gas, pushes receipts, updates gas/section accounting, and bumps the BAL index. Final semantic state materialization is pipelined on a scoped worker while ordered receipt/accounting commit runs, then the final covered semantic storage values are committed once. It does not serially replay semantic plans after the final worker finishes, and it does not skip materializing the state changes.

## Sequential Dependencies and Initial Strategies

| Domain | Evidence | Initial strategy |
| --- | --- | --- |
| sender nonce | `TempoBlockExecutor::execute_transaction_without_commit`; transaction-pool same-sender invalidation in `crates/transaction-pool/src/best.rs` | `SerialConflictDomain` for same sender, `AlwaysReexecute` on nonce read conflict |
| expiring nonce | `crates/revm/src/handler.rs`; `NonceManager::check_and_mark_expiring_nonce`; `EXPIRING_NONCE_SET_CAPACITY` in `crates/precompiles/src/nonce/mod.rs` | worker semantic reduction with `ExpiringNonceUse` and ordered covered-write synthesis |
| fee payer balance | `TipFeeManager::collect_fee_pre_tx`; `TIP20Token::transfer_fee_pre_tx`; `TempoPooledTransaction::fee_balance_slot` | `OrderedValidationOnly` plus `Tip20FeeEscrowDelta` for pure TIP20 |
| fee token liquidity | `TipFeeManager::collect_fee_pre_tx`; `tip_fee_manager::amm::{compute_amount_out, execute_fee_swap}` | `AlwaysReexecute` or `SerialConflictDomain` outside default PathUSD path |
| validator fee credit | `TipFeeManager::collect_fee_post_tx`; `increment_collected_fees`; `TempoTxResult::validator_fee` | `CommutativeAccumulator` through `CollectedFeesDelta` when validator token is stable |
| keychain/auth state | `crates/precompiles/src/account_keychain/mod.rs`; `crates/revm/src/handler.rs` key authorization and spending-limit code | `OrderedValidationOnly` when EVM read set is independent, otherwise `AlwaysReexecute` |
| native balance transfer | `TempoBlockExecutor` real EVM execution and account read/write capture | `AlwaysReexecute` on conflicts |
| TIP-20/ERC-20 balance | `TIP20Token::_transfer`; `tip20_slots::BALANCES`; prewarming balance-touch helpers | worker semantic reduction only for registered pure TIP20 PathUSD transfer fixture, otherwise `AlwaysReexecute` |
| TIP-20/ERC-20 allowance | `TIP20Token::transferFrom`; `tip20_slots::ALLOWANCES` | `SerialConflictDomain` or `AlwaysReexecute` |
| token supply/protocol fee | `TIP20Token::mint`, `burn`, `total_supply`, rewards fields | `AlwaysReexecute`/barrier |
| AMM pool liquidity/reserves | `crates/precompiles/src/tip_fee_manager/amm.rs`; transaction-pool `amm.rs` | `SerialConflictDomain` or `AlwaysReexecute`; no AMM action replay in first version |
| order book/order fill | `crates/precompiles/src/stablecoin_dex/mod.rs`, `order.rs`, `orderbook.rs` | `SerialConflictDomain` or `AlwaysReexecute` |
| shared counters/global singletons | fee manager, nonce manager, factories, registries from `crates/precompiles/src` | `AlwaysReexecute` unless explicitly modeled |
| account creation/code deployment/code reads | EVM account/code reads via tracking DB and `CREATE` state writes | `AlwaysReexecute` |
| precompile/system-contract side effects | `crates/precompiles/src/*`; `crates/revm/src/handler.rs` | explicit action for modeled nonce/TIP20/fee paths, otherwise `AlwaysReexecute` |
| builder gas/lane/block-size limits and state-aware pool feedback | `TempoPayloadBuilder::build_payload`; `StateAwareBestTransactions::on_new_result` | ordered serial builder accounting in commit phase |
| system tx/subblock/finalization | `build_seal_block_txs`, subblock loop, system tx loop, `builder.finish` | serial barrier outside Block-STM normal-pool path |

## Required Semantic Actions

- `ExpiringNonceUse`: captured in `action/production.rs` from the successful real execution result plus expiring-nonce transaction fields. Covered slots are generated by `action/slots.rs`: `NONCE_PRECOMPILE_ADDRESS` ring pointer, deterministic ring slot, and `seen[hash]`.
- `Tip20FeeEscrowDelta`: captured in `action/production.rs` from the real fee-token writes and production fee math. Covered slots are generated by `tip20_balance_key(token, payer)` and `tip20_balance_key(token, TIP_FEE_MANAGER_ADDRESS)`.
- `Tip20TransferDelta`: captured in `action/production.rs` only for simple PathUSD `transfer`/`transferWithMemo` calls whose successful real write set matches registered pure TIP-20 balance semantics. Covered slots are `tip20_balance_key(token, sender)` and `tip20_balance_key(token, recipient)`.
- `CollectedFeesDelta`: captured in `action/production.rs` from `TempoTxResult::validator_fee` and the beneficiary. Covered slot is `fee_manager_collected_fees_key(beneficiary, validator_token)`.
- `SemanticPrefixRead`: represented by `action/semantic_read.rs`; the production pure TIP-20 plan uses ordered guard validation for fee precharge and transfer debits, and exact covered reads remain a re-execution/barrier case.
- Slot derivation uses the production-generated `tempo_precompiles::tip20::tip20_slots` constants through `action/slots.rs`: `TOTAL_SUPPLY`, `BALANCES`, and `ALLOWANCES`. The implementation does not rely on hard-coded TIP-20 mapping slot numbers.

## Test Harness Locations

- Core, overlay, policy, action, metrics, and benchmark unit tests: `crates/payload/builder/src/blockstm/*`.
- Production payload builder tests: co-located in `crates/payload/builder/src/blockstm/executor.rs` and `crates/payload/builder/src/lib.rs` where access to private builder seams is needed.
- Real EVM fixtures: `crates/payload/builder/src/blockstm/state_view.rs` tests first; if production EVM harness reuse is required, use `crates/evm/src/test_utils.rs`.
- Ignored node E2E: `crates/node/tests/it/blockstm.rs` registered from `crates/node/tests/it/main.rs`, test name `blockstm_node_e2e_starts_with_flag_and_builds_serial_equivalent_block`.
- Final script: `scripts/check-blockstm-builder.sh`.

## Completion Gates

The final gate is `./scripts/check-blockstm-builder.sh`. It runs formatting, documentation checks, all required `blockstm_*` test groups, `cargo build --workspace --bins`, the ignored node E2E, the existing pure TIP20 Criterion baseline, and the new Block-STM Criterion benchmark. The script parses the existing baseline median throughput and passes it as `TEMPO_EXISTING_TIP20_BASELINE_TPS`; the Block-STM release gate fails unless the new 25000 tx builder benchmark is exact-output equivalent, over 2x faster than same-harness release serial, over 2x faster than the parsed existing release Criterion baseline, at least 500000 TPS for the full builder path, and at least 500000 TPS for the semantic path. The original ignored test still documents the 1.5x median-throughput target from the initial goal file, but release completion now uses `cargo bench`/Criterion, not `cargo test`, for performance.

Known conservative fallbacks:

- Unknown contract storage, account/code creation, token supply/admin/pause/reward modes, and precompile/system side effects outside the registered pure TIP-20 path use `AlwaysReexecute`.
- AMM and order-book domains are classified explicitly and remain serial-domain/re-execution paths until a serial-equivalent resolver exists.
- System transactions, subblocks, finalization, block limits, and state-aware pool feedback stay in the ordered builder commit/accounting phase.
