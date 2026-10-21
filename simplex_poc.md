# Simplex PoC log

Running log of decisions, deviations from `simplex.md`, and problems hit while implementing the
Simplex proof of concept for zones. Newest entries are appended at the end of each section.

## Scope decisions

- **Simplex is the only multi-sequencer path.** A manifest means Simplex; the portal-elected
  leader/follower role controller, follower block import, the bespoke replication and backfill
  protocol, follower settlement signatures (`SettlementManager`), the leadership schedule, forced
  recovery, the `zone_setLeader`/`zone_getSequencerInfo` operator RPC, `--sequencer.role`, and
  the `rpc_only` shadow prover are deleted. The `[consensus]` table is optional (defaults apply)
  and the manifest schema no longer knows `leader_ed25519_public_key`, `historical_leaders`,
  `[forced_recovery]`, or `rpc_only`. Without a manifest, `tempo-zone --sequencer` and
  `tempo-zone dev` still run the single-node `ZoneEngine` for development (open question 2 in
  `simplex.md` §12 is still open).
- **No migration.** An existing leader/follower zone cannot be switched to a Simplex manifest in
  place; a cutover procedure is a separate piece of work.
- **Fresh zones only.** Marshal always starts from `Start::Genesis`; an existing zone with
  history and no Simplex certificates cannot be migrated (review §7). No cutover procedure.
- **Static membership.** One epoch (`FixedEpocher(2^40)`), participants from the manifest (review
  §8). Membership changes are unsupported.
- **No `rpc_only` nodes.** A passive replica needs marshal fed by finalization certificates
  without a voting Simplex instance; out of PoC scope, so the manifest has no such role. The
  shadow prover (`zone_sequencer::ShadowProver`) and the L1 subscriber's finalized-batch channel
  it consumed are no longer wired from the node and wait for that follow-mode design.
- **Four voters minimum.** Simplex manifests require ≥ 4 quorum nodes (option A in §5.3).

## Reuse vs copy (review §2)

- Reused `tempo_consensus::consensus::{Block, Digest}`, `storage::{Hybrid,
  init_finalized_blocks}`, and `network::limit_channel` by widening their visibility instead of
  copying them into the zone crate. `Block` keeps its `CertifiableBlock` impl; `Inline` never
  calls it.
- `storage::init_finalizations_archive` was BLS-only; it is now generic over the certificate
  scheme so zones' ed25519 finalizations share the archive layout (one L1 test needed a turbofish).
- `Hybrid`'s `FinalizedBlocksProvider` impl is for the concrete `BlockchainProvider`; the zone
  add-ons are generic over the node provider, so `zone-consensus` adds a small wrapper
  (`provider::FinalizedBlocks`) with the same finalized-only semantics.
- The executor is a reduced zone executor, not the L1 actor (see "Executor").

## Deposit queue (review §5)

- The design proposed per-deposit indices to filter owed events. Zone deposits carry no index,
  so instead the queue tracks `consumed_through` (the Tempo checkpoint of the last applied
  finalized block) and exposes an atomic `snapshot`. A proposal/verification walks its parent's
  *unfinalized* ancestry (blocks whose anchor is above `consumed_through`) and finds the newest
  unfinalized full import `X`:
  - no such `X`: owed work = finalized deferred work + pending blocks in `(consumed, anchor]`;
  - otherwise: owed work = pending blocks in `(X, anchor]`.
  This preserves deferred work crossed by finalized checkpoint-only blocks (review §5) and keeps
  the existing `follows_checkpoint_blocks` batch-boundary semantics (the work list has more than
  one entry exactly when checkpoint-only blocks happened since the last full import).
- `seed_consumed_through` is called at startup with the finalized block's checkpoint. When
  seeded, the first enqueued L1 block must extend it.
- The L1 subscriber gained `checkpoint_zone_block`: Simplex nodes resume ingestion from their
  *finalized* block, because reth's canonical head may be an unfinalized (replaceable) block.

## Executor

- Single actor, one engine call at a time, finalized blocks prioritized (`biased` select).
- It never fetches from peers. `propose`/`verify` walk marshal's ancestry stream and hand the
  executor every ancestor reth may not have executed (canonical-by-hash lookup; side-chain blocks
  reth already executed are cheap to resubmit).
- Reth ignores FCU to a canonical *ancestor* (it does not update the finalized marker in that
  branch). The finalize FCU therefore keeps the current canonical head when it descends from the
  finalized block, and otherwise reorgs to the finalized block.
- Finalization waits for the L1 tracker to observe the block's anchor before consuming the queue,
  so a node that restarts with reth behind marshal does not defer/confirm before the subscriber
  re-enqueued those L1 blocks (otherwise deposits would be silently dropped from deferred work).
- Startup replays `(reth finalized, marshal processed]` from marshal's archive (reth persists
  lazily). Marshal restores its processed height from its own metadata, so `Start::Genesis` is
  correct on every restart.

## Consensus wiring

- Signing namespace = zone P2P namespace (L1 chain id, portal, zone id, wire version) + `_SIMPLEX`.
- `RoundRobin::shuffled(namespace)` elector.
- Simplex floor is always `Floor::Genesis(genesis)`; the vote journal restores progress, as on L1.
- All five consensus channels use a 128/s quota; L1 limits marshal to 8/s, which would make a
  disk-loss resync of a few hundred blocks needlessly slow for a four-node trusted fleet.
- The network/runtime lives in `zone-p2p::simplex` (no reth dependency); consensus runs on the
  same Commonware context through a closure. Transactions are forwarded unconditionally to every
  other quorum member, no leadership routing.
- Manifest `[consensus]` carries the timing table (`*_ms` keys, §7 defaults) and the settlement
  failover delay; orderings that Commonware asserts at runtime are rejected at parse time.
- Beneficiary rule (§6.3): a leader's proposals must pay the manifest `beneficiary` of that leader,
  defaulting to the local shared sequencer address. A proposer uses the same lookup for itself,
  so only a node whose manifest disagrees with its peers produces invalid blocks (that is how
  `test_simplex_rejects_invalid_proposals` creates a rogue proposer). `membership_digest` does
  not cover `beneficiary`, so such a mismatch is not visible in the startup log.
- Zone header invariants (§6.2) are checked in `verify` (`consensus_context` absent, empty
  `extra_data`) rather than in a zone-specific `Block` constructor, since the L1 wrapper is reused.

## Things that went wrong

- **Spike's static peer provider is wrong at runtime.** Appendix A says a static
  `commonware_p2p::Provider` can return a subscription "whose sender is dropped" so it never
  fires. In practice a closed channel yields `None` immediately and the buffered broadcast engine
  treats that as shutdown, so the whole consensus stack stopped ~5 ms after start. Fix: the
  `lookup::Oracle` already implements `Provider` over the tracked peer set (the manifest quorum
  registered at id 0), so the custom provider was deleted and the oracle is passed to both the
  broadcast engine and the marshal resolver. The type-check spike could not catch this.
- **`Handle::select` hid which actor stopped.** Replaced with `select_all` + names so the error
  says `Zone consensus actor \`broadcast\` stopped`.
- **Ancestry walk at genesis.** The first proposal's parent is genesis (no `advanceTempo`); the
  walk broke out of its loop into the "ancestry too long" error. Genesis now terminates the walk.
- **Reth reports no `finalized` block at genesis**, so `eth_getBlockByNumber("finalized")` is
  `null` until the first Simplex finalization. The harness treats that as height 0.
- **Checkpoint starvation when L1 outpaces consensus.** With the in-process real L1 at 250 ms
  per block and four in-process Simplex nodes at ~2.6 zone blocks/s, the queue always held more
  than one header after the parent. `tempo_import_decision` reserves only the *last* queued
  header for a full import, so every zone block was checkpoint-only: hundreds of blocks
  finalized, but no deposit was processed and no withdrawal batch ever closed (only the first
  batch settled). The legacy engine hides this by producing blocks back-to-back. Fix in
  `select_import`: a block whose parent was checkpoint-only uses a full import whenever the
  hardfork/finalized-target rules allow one, so a lagging zone alternates checkpoint and full
  imports and still catches up (each checkpoint takes up to 1 024 headers). This is a
  proposer-side policy; verifiers never checked the import decision.
- **Restarting a node inside the test process.** A crashed in-process reth node keeps MDBX
  (`EAGAIN`) and RocksDB (`LOCK`) locks until every background thread drops its handle, so
  reopening the same datadir fails. The harness restarts a node from a byte copy of its datadir
  at a fresh path, which is what a new process would see after a crash.
- **Deferred-work window after restart (fixed).** When a node restarts from a finalized
  checkpoint that crossed checkpoint-only blocks, the L1 subscriber restores the deferred portal
  work asynchronously after connecting. A verification in that window would have computed the
  owed work without it and *rejected* a valid full import. `seed_consumed_through` now takes
  `deferred_work`, and `snapshot()` returns `None` (propose skips, verify abstains) until
  `restore_deferred` runs.

## Settlement (review §1 and §4)

- **Threshold one, as the design proposes, with the review's caveat accepted for the PoC.** Every
  quorum node submits a self-signed attestation through the existing "legacy 1-of-1" path
  (`certificate = None`), and node startup refuses a Simplex manifest unless the portal's
  `sequencerThreshold` is 1. This is a *trusted-operator* model: one compromised individual key
  can settle a valid alternative extension of the portal anchor (review §1). It is **not**
  tolerant of one Byzantine sequencer end to end, even though consensus is. Detection exists but
  prevention does not: if the portal advances to a block that is not on a node's finalized chain,
  that node's monitor cannot resolve the portal anchor to a canonical local block and fails
  closed (it stops settling and logs on every retry). Production should use quorum attestations
  of Simplex-finalized batches, or on-chain certificate verification.
- **Finality gate.** With a settlement duty configured, `BatchPreparer` scans only through
  `min(last persisted block, reth finalized block)`, so a locally visible but unfinalized batch
  boundary is never proven or submitted. Not covered by an e2e test: forcing a boundary block to
  become canonical without finalizing needs a fault-injection hook in consensus.
- **Duty rotation and failover.** `owner(batch) = sorted(quorum secp256k1 addresses)[index mod
  n]`. A non-owner waits until the portal settles that exact batch (then advances its cursor
  without submitting) or until `settlement_failover` passes. The design measured failover in L1
  blocks; the PoC uses wall-clock time from when the batch is ready locally (manifest
  `settlement_failover_ms`, default 30 s). The first failover run had all three survivors fail
  over at the same instant (two reverted duplicates), so takeover is staggered by rotation rank:
  the next sequencer after the owner waits one delay, the one after it two, and so on. A
  duplicate submission still reverts on `prevBlockHash`; the pre-submit portal read then sees the
  batch settled and treats it as done.
- **Withdrawals.** The withdrawal processor uses the same owner rule per queue head slot, with
  the same failover. A node that did not submit a batch has no cached withdrawal payloads for
  it; when it takes a slot over, the existing repair path rebuilds them from chain data.

## Not done in the PoC (and why)

- **Legacy e2e coverage that had no Simplex equivalent was dropped rather than ported:**
  `handoff_e2e.rs` (portal leadership handoff), `network_chaos_p2p_e2e.rs` and
  `network_chaos_e2e.rs` (partitions, latency, and L1 outages against the leader/follower
  topology; Simplex's own liveness is Commonware's to test), the 2-of-3 certificate tests in
  `l1_e2e.rs`, and two already-ignored follower tests in `e2e.rs`. `proof_wal.rs` now checks
  witness persistence on a four-node Simplex quorum instead.
- **No CLI `--consensus.*` flags or status RPC** (§6.11, §6.12). Timing comes from the manifest's
  `[consensus]` table; tests read finality through `eth_getBlockByNumber("finalized")`. The
  operator RPC context (`SequencerRpcContext`) is not installed in Simplex mode.
- **No `rpc_only` replicas, no snapshot sync, no migration of existing zones, static membership.**
- **Single-sequencer dev mode unchanged.** `tempo-zone dev` and the injection-based e2e tests
  still run the single-node `ZoneEngine`; a one-node Simplex instance is not exercised (open
  question 2).
- **Prover-backed settlement on Simplex nodes is not e2e-tested.** `proof_wal.rs` checks that
  every node persists a witness for every finalized block and that a failing proof store stops the
  node, but the settlement tests run without a prover (NoProof verifier fallback).
- **Executor scope (review §6).** The reduced executor serializes engine calls and prioritizes
  finalization, but it has no build arbitration, no convergence of reth's head to the consensus
  tip, and no metrics. A stale build result is harmless (the proposal future is dropped and the
  built block is just an orphan in reth's tree). Reth's canonical head can be an unfinalized
  block (the parent of the last local build), so RPC `latest` may briefly show a block Simplex
  later orphans; `finalized` is authoritative.

## E2E tests

Run with CI's stack size (some legacy tests in the same binary overflow the default 2 MiB test
thread stack):

```bash
RUST_MIN_STACK=8388608 cargo test -p zone-node --test it simplex
```

`crates/zones/node/tests/it/simplex_e2e.rs` — four in-process Simplex nodes over synthetic L1
injection (`SimplexCluster`), short views (`leader_timeout` 1 s):

| Test | What it proves |
|---|---|
| `test_simplex_finalizes_with_rotating_leaders` | identical finalized chain on all nodes; ≥ 3 distinct proposers |
| `test_simplex_includes_forwarded_transactions_and_deposits` | a tx sent to one node reaches every pool and is included; deposits mint exactly once |
| `test_simplex_survives_crashed_leader` | one node crashed: 8 more blocks finalize, none proposed by the crashed node, no operator action |
| `test_simplex_restarted_node_catches_up` | node down for 10 blocks restarts from disk, backfills via marshal, votes again |
| `test_simplex_node_recovers_from_disk_loss` | wiped datadir: node resyncs every finalized block from peers |
| `test_simplex_late_anchor_observation_waits_instead_of_rejecting` | a node missing an L1 observation abstains (does not reject); applies the block once observed |
| `test_simplex_halts_without_quorum_and_resumes` | 2 of 4 down: nothing finalizes; one returns: progress resumes |
| `test_simplex_checkpoint_catch_up_preserves_deposits` | 6 queued anchors become checkpoint + full imports; deposits crossed by checkpoints mint exactly once |
| `test_simplex_rejects_invalid_proposals` | a node with a disagreeing manifest beneficiary proposes invalid blocks; others reject them; none finalize |
| `test_simplex_whole_fleet_restart_resumes` | all four nodes crash and restart; finalized history unchanged; progress resumes |

`crates/zones/node/tests/it/simplex_settlement_e2e.rs` — four Simplex nodes against the
in-process Tempo L1 and a real `ZonePortal` (threshold 1):

| Test | What it proves |
|---|---|
| `test_simplex_settles_with_rotating_duty` | ≥ 4 batches settled, each by its duty owner, ≥ 2 distinct submitters, no batch settled twice, settled hash finalized everywhere |
| `test_simplex_settlement_fails_over_from_crashed_owner` | the next owner is crashed; its batch is settled by another node after the failover delay |

Not covered by e2e (see above): unfinalized-boundary settlement, prover-backed settlement on
Simplex nodes, network partitions/latency (the legacy chaos proxies were not ported), multiple
checkpoint-only blocks *across a restart* (the synthetic harness cannot re-fetch deferred L1 work;
the real subscriber can).

## Verification status (end of PoC session)

- All 12 Simplex e2e tests pass (`RUST_MIN_STACK=8388608 cargo test -p zone-node --test it simplex`, ~80 s),
  plus `proof_wal`, `test_p2p_listener_failure_stops_node`, `test_sequencer_exposes_simulation_endpoints`,
  and `hardfork_settlement_e2e` after the legacy-path removal.
- Unit tests of every touched crate pass: `tempo-consensus`, `zone-l1`, `zone-p2p`,
  `zone-sequencer`, `zone-consensus`, `zone-node` (lib).
- Single-sequencer regression sample after the legacy-path removal (injection e2e, restart):
  7 passed.
- `cargo clippy --tests` clean on touched crates, `cargo +nightly fmt` applied, `zepter` clean.
- Nothing committed.
