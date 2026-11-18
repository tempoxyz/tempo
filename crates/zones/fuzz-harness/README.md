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
TIP-1160 transfer opt-in, TIP-20 pause flags, the TIP-1022 address registry,
TIP-1108 commitments). Blocks execute with the zone node's `ZoneEvmConfig` and
block executor, from the zone dev genesis, on hardforks T13 and later. Every
block opens with the `advanceTempo` system transaction the sequencer adds, and
closes with `finalizeWithdrawalBatch` when it left withdrawals pending; their
receipts come first and last in the block's outcome.

Zones run no stablecoin DEX, so its invariants are skipped.
