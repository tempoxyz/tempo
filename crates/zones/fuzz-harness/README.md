# Zone Fuzz Harness

Tempo Zone's stateless block executor, built as a cdylib for fuzzing and replay.
It is [`tempo-fuzz-harness`](../../fuzz-harness) on a zone: the same C ABI,
outcomes and protocol invariants, from
[`tempo-fuzz-engine`](../../fuzz-engine), so the same loader runs either.

```bash
cargo build -p zone-fuzz-harness --release
```

An input is a `ZoneHarnessInput`: a `TempoHarnessInput` whose chain ID is a
zone chain ID, with the Tempo L1 the zone reads, one of:

- `State`: fixed L1 storage and TIP-1108 commitments (the portal's TIP-1160
  transfer opt-in and token configuration, TIP-20 pause flags, the TIP-1022
  address registry), the same at every L1 block. Each zone block imports a
  header made up as the child of the last.
- `Chain`: a Tempo chain from its genesis, which the harness executes first
  with the Tempo engine. Zone block `i` imports Tempo block `i`'s header and
  reads Tempo's state after it, as a sequencer anchors each zone block to the
  next Tempo block, so the zone sees what Tempo transactions did. The zone
  takes the chain's hardfork schedule and its blocks' timestamps, and may have
  no more blocks than the chain; what the chain breaks is reported with its
  subjects prefixed `on Tempo:`.

Blocks execute with the zone node's `ZoneEvmConfig` and block executor, after
its consensus checks, from the zone dev genesis, on hardforks T13 and later;
`Transaction` inputs are not supported.

A block whose header the harness builds opens with the `advanceTempo` system
transaction the sequencer adds, and closes with `finalizeWithdrawalBatch` when
it left withdrawals pending; their receipts are `TxIndex::Synthesized`. A block
given as an RLP header executes exactly its own transactions, as the node
imports it, so a zone block replays with its own `advanceTempo`.

Zones run no fee AMM or stablecoin DEX, so their invariants are skipped. A zone mirrors Tempo's
configurable account commitments rather than keeping its own, so in place of the TIP-1107 account
invariants every step from T14 checks TIP-1154 (`TEMPO-ZONE-ACCOUNT-*`, in
[`tempo-invariants`](../../invariants/src/zone_account)): what the zone shows of its system
contracts, the input's accounts and those L1 commits to (up to 32), against L1's commitments at the
zone's anchor.
