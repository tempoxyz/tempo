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
  transfer opt-in, TIP-20 pause flags, the TIP-1022 address registry), the same
  at every L1 block. Each zone block imports a header made up as the child of
  the last.
- `Chain`: a Tempo chain from its genesis, which the harness executes first with
  `tempo-fuzz-engine`'s Tempo engine. Zone block `i` imports Tempo block `i`'s
  header and reads Tempo's state after it, as a sequencer anchors each zone
  block to the next Tempo block, so the zone sees what Tempo transactions did,
  such as registering a configurable account. The zone takes the chain's
  hardfork schedule and its blocks' timestamps, and may have no more blocks
  than the chain; what the chain breaks is reported prefixed with `on Tempo:`.

Blocks execute with the zone node's `ZoneEvmConfig` and block executor, from
the zone dev genesis, on hardforks T13 and later. Every block opens with the
`advanceTempo` system transaction, built by the same zone-evm function the
sequencer's payload builder uses, and closes with `finalizeWithdrawalBatch`
when it left withdrawals pending; their receipts come first and last in the
block's outcome. As the sequencer's builder does, a block leaves out the
input's transactions the zone rejects, and system and subblock transactions.
A zone pre-state holding `0xef` code outside the zone genesis (the account
marker or a delegation), which a zone never stores, is invalid.

Besides the Tempo protocol invariants, every step checks the zone's TIP-1154
configurable accounts (`TEMPO-ZONE-ACCOUNT-*`, in
[`tempo-invariants`](../../invariants/src/zone_account)) against Tempo at the
zone's anchor: the accounts the input's transactions are signed by or act for,
its pre-state lists, and L1 commits to, up to 32. They replace the TIP-1107
account invariants, since a zone mirrors Tempo's commitments rather than
keeping its own. Zones run no stablecoin DEX, so its invariants are skipped.
