# Zone Fuzz Harness

Tempo Zone's stateless block executor, built as a cdylib for fuzzing and replay.
It is [`tempo-fuzz-harness`](../../fuzz-harness) on a zone: the same C ABI,
outcomes and protocol invariants, from
[`tempo-fuzz-engine`](../../fuzz-engine), so the same loader runs either.

```bash
cargo build -p zone-fuzz-harness --release
```

An input is a `ZoneHarnessInput`: a `TempoHarnessInput` whose chain ID is a
zone chain ID, with the Tempo L1 storage the zone reads (the portal's
TIP-1160 transfer opt-in and token configuration, TIP-20 pause flags, the
TIP-1022 address registry, TIP-1108 commitments). Blocks execute with the zone
node's `ZoneEvmConfig` and block executor, after its consensus checks, from the
zone dev genesis, on hardforks T13 and later; `Transaction` inputs are not
supported.

A block whose header the harness builds opens with the `advanceTempo` system
transaction the sequencer adds, and closes with `finalizeWithdrawalBatch` when
it left withdrawals pending; their receipts are `TxIndex::Synthesized`. A block
given as an RLP header executes exactly its own transactions, as the node
imports it, so a zone block replays with its own `advanceTempo`.

Zones run no fee AMM or stablecoin DEX, so their invariants are skipped.
