# Simplex consensus for Tempo Zones — technical design (proof of concept)

Status: design, no code yet. Scope: a proof of concept that replaces the portal-driven
leader/follower multi-sequencer protocol in `crates/zones/*` with commonware Simplex, mirroring
the Tempo L1 consensus stack in `crates/consensus` wherever the zone constraints allow.

All paths are relative to the repository root. Line numbers refer to commit `8a4c273d07`.

---

## 0. Summary

Today a zone is run by a fleet of up to eight sequencers where exactly one node, the portal's
`leader`, builds blocks. Followers re-execute and persist the leader's blocks and sign EIP-712
settlement attestations so the leader can assemble a `sequencerThreshold`-of-n certificate for
`ZonePortal.submitBatch`. Leadership changes only when an admin or sequencer calls
`ZonePortal.setLeader`, or through an operator-driven forced-recovery directive in the manifest.

The target design:

- **Consensus.** Every quorum sequencer runs a commonware Simplex engine over the zone block
  stream, exactly as L1 validators do, with a round-robin leader per view. A leader crash costs
  one `leader_timeout` and the next view's leader continues from the same parent. No portal
  `setLeader`, no forced recovery, no role controller.
- **Replication and durability.** commonware `marshal` delivers finalized blocks in order to every
  node, stores them in its own archive the moment they finalize (independent of reth's lazy
  persistence), and backfills gaps from peers. A node that loses its disk resyncs from any
  surviving peer. This is the same `marshal` + "hybrid" store design L1 uses.
- **Settlement.** The portal already accepts `sequencerThreshold == 1` and never reads `leader`
  in `submitBatch`. The PoC sets the threshold to 1 and drops the follower-signature protocol
  entirely: the proof (SPF + Nitro attestation) carries correctness. A deterministic
  settlement-duty rotation, with time-based failover to any other sequencer, decides who calls
  `submitBatch` and `processWithdrawals`. **No Solidity change is needed for the PoC.**
- **Block content is unchanged.** Zone blocks still import exactly one finalized Tempo header per
  full block (or a checkpoint range), carry the same system transactions, and are proven by the
  same SPF. Blocks do not embed a consensus context in the header because the stateless prover
  hard-codes `consensus_context: None`; Simplex is run with marshal's `Inline` wrapper, which
  does not need it.

Two differences from L1 are deliberate and explained in §5: zones use the ed25519 Simplex
signing scheme with a `RoundRobin` elector instead of BLS threshold signatures, DKG and the VRF
elector, and zones run a single never-ending epoch with a static participant set from the
manifest.

One consequence to decide early (§5.3): commonware's fault model is `n ≥ 3f + 1`. Three
sequencers tolerate **zero** faults. To survive one crashed node the fleet needs four quorum
members. A three-node crash-tolerant variant is possible with a custom fault model but is not
what L1 runs.

---

## 1. Goals and non-goals

Goals, taken from the request:

1. Replace the multi-sequencer leader/follower consensus with Simplex, as close to L1 as the
   zone's constraints permit.
2. `submitBatch` is called by one sequencer with a 1-of-n certificate; the prover is the
   correctness guarantee. No settlement quorum.
3. Several zone nodes build blocks for the same zone with rotating leadership; every node executes
   and persists every block so the chain, including the state behind every submitted batch, is
   recoverable from any node.
4. Automatic leader rotation on crash. The zone never stalls on one machine, never bricks, and
   never corrupts.
5. Scope all work and produce a build plan for a proof of concept.

Non-goals for the PoC (tracked in §13):

- On-chain validator-set changes, epochs and DKG.
- Verifying a Simplex certificate inside `ZonePortal` instead of EIP-712 signatures.
- Snapshot sync, follow mode over RPC, deferred verification.
- Removing the vestigial `leader` fields from `ZonePortal` (requires a Tempo hardfork).
- Production hardening, metrics parity, and operator tooling beyond what tests need.

---

## 2. Current architecture (as-is)

### 2.1 Roles, leadership, and the role controller

- A node's identity is a Commonware ed25519 key (`--p2p.key`) plus an optional individual
  secp256k1 key (`--secp256k1.key`) whose address must be in the portal sequencer set. Every
  node that can produce blocks also holds the **shared sequencer key** (`--sequencer-key-file`),
  which is the block beneficiary signer and the ECIES deposit-decryption key
  (`crates/zones/node/src/cli.rs:462-473`).
- The static topology is a TOML manifest (`crates/zones/p2p/src/manifest.rs`): `nodes[]` with
  `name`, `ed25519_public_key`, `secp256k1_address`, `address`, `rpc_only`; a bootstrap
  `leader_ed25519_public_key`; optional `historical_leaders` and `forced_recovery`.
  `MIN_QUORUM_NODES = 3` (`manifest.rs:17`).
- Live leadership comes from finalized portal state: `leader`, `leaderEpoch`,
  `leaderActivationTempoBlock` and the `LeaderUpdated` event. The L1 subscriber applies each
  transition to a `LeadershipSchedule` through `ScheduleLeadershipSink`
  (`crates/zones/node/src/node.rs:1023-1077`), and `seed_leadership_schedule` bootstraps it from
  a multicall at the local Tempo anchor (`node.rs:1163-1232`).
- The **role controller** (`crates/zones/node/src/role.rs`) derives the desired role for the
  *next* Tempo anchor: `schedule.leader_for(checkpoint + 1)` is this node → leader generation,
  else follower generation, else fenced (`role.rs:446-483`). It tears down and rebuilds the
  whole task graph on a role change (`start_generation`, `role.rs:842-1050`).
- The leader generation runs `ZoneEngine` with a `ProductionPermit` that stops production at the
  first anchor the schedule assigns to someone else (`crates/zones/node/src/engine.rs:65-115,
  534-554`), the persisted-block broadcaster, follower-signature collection, transaction import,
  and the sequencer background tasks (`ZoneMonitor` + withdrawal processor).
- The follower generation runs `FollowerBlockSync` (`crates/zones/node/src/follower.rs`), which
  imports live blocks only from `leader_for(anchor)` (`follower.rs:721-747`), validates the L1
  header range against the local checkpoint (`follower.rs:882-913`), waits up to 30 s for the
  local L1 subscriber to observe the embedded anchor (`follower.rs:804-825`), checks the
  `advanceTempo` deposit and token inputs against locally observed portal events
  (`follower.rs:764-802`), executes via `new_payload` + `fork_choice_updated`, and then advances
  the deposit queue (`follower.rs:652-717`). It also signs settlement proposals
  (`follower.rs:391-444`) and runs backfill.
- Forced recovery (`manifest.rs:95-170`, `node.rs:1091-1161`) is the only way to recover from a
  crashed leader without the leader's `setLeader` cooperation: operators restart every node with
  a directive naming a replacement leader and a canonical block hash.

### 2.2 Block production

`ZoneEngine` (`engine.rs:176-462`) is L1-event driven: it peeks the `DepositQueue`
(`crates/zones/l1/src/queue.rs`), decides between a full import and a checkpoint-only import
(`tempo_import_decision`, `engine.rs:568-633`), decrypts deposits
(`L1BlockDeposits::prepare_many`, `crates/zones/l1/src/block.rs:17-54`), builds
`ZonePayloadAttributes { inner, timestamp_millis_part, tempo_import }`
(`crates/zones/payload/src/attrs.rs:60-75`), sends FCU-with-attributes through the reth engine
handle, resolves the payload, submits `new_payload`, collects and persists the execution witness
(`ProofCollectorHandle::collect_and_persist`), confirms the queue entry, and finally sends a bare
FCU with head = safe = finalized = the new block ("instant finality", `engine.rs:38-39`).

The payload builder (`crates/zones/payload/src/builder.rs`) executes `advanceTempo` or
`advanceTempoHeaders` first, then pool transactions, then `finalizeWithdrawalBatch` when
`should_finalize_withdrawal_batch` says the block closes a batch (`builder.rs:597-620`). It sets
`consensus_context: None` (`builder.rs:239`). The default batch cadence is 120 zone blocks
(`DEFAULT_WITHDRAWAL_BATCH_INTERVAL_BLOCKS`).

### 2.3 Replication and P2P

`crates/zones/p2p` already runs a dedicated `commonware_runtime::tokio::Runner` on its own OS
thread (`runtime.rs:340-401`) hosting a `commonware_p2p::authenticated::lookup::Network` with
ed25519 identities from the manifest (`network.rs:62-174`). It registers six channels:
`BLOCK_CHANNEL = 0`, `BACKFILL_REQUEST_CHANNEL = 1`, `BACKFILL_RESPONSE_CHANNEL = 2`,
`TRANSACTION_CHANNEL = 3`, `SETTLEMENT_PROPOSAL_CHANNEL = 4`, `SETTLEMENT_SIGNATURE_CHANNEL = 5`
(`network.rs:16-27`). Block replication (`replication.rs`) broadcasts only **persisted** blocks,
with careful drain logic at demotion, and a bespoke paged backfill protocol
(`crates/zones/p2p/src/backfill.rs`, `replication.rs:469-573`). The routing policy
(`routing.rs`) gates every message on leadership state.

### 2.4 Settlement

- `ZoneMonitor` (`crates/zones/sequencer/src/monitor.rs`) watches the persisted zone chain for
  `BatchFinalized` events, builds `BatchData` (`settlement.rs:1307-1332`), prepares an anchor,
  runs the SPF/Nitro prover, and collects a certificate via `SettlementManager::prepare`
  (`settlement_manager.rs:429-493`), which broadcasts the EIP-712 `SettlementAttestation`
  (`attestation.rs:819-845`) to followers and waits for `sequencerThreshold` signatures.
- `BatchSubmitter::submit_batch` (`settlement.rs:392-520`) submits either the collected
  certificate or, when `certificate` is `None` ("legacy 1-of-1 mode"), a single self-signed
  attestation (`settlement.rs:448-470`). The withdrawal processor then calls
  `processWithdrawals`.
- Contract facts (from `crates/zones/contracts/src/runtime/tempo/ZonePortal.sol`):
  `submitBatch` is `onlySequencer` (any active member), requires
  `blockTransition.prevBlockHash == blockHash`, a certificate with at least `sequencerThreshold`
  distinct active signers over `SETTLEMENT_ATTESTATION_TYPEHASH` (ZP:1458-1523), continuity of
  deposit and token cursors, and `IVerifier.verify`. It never reads `leader`. `leader` is read
  only in `setLeader`, `_setLeader`, and the `ActiveLeaderRemoved` guard of `_replaceSequencerSet`
  (ZP:403-407). The native Nitro verifier (`crates/precompiles/src/zone_verifier/mod.rs`) binds
  the batch transition, anchors and cursors; it binds no beneficiary, leader, or signer set.
  `sequencerThreshold` may be 1 (`_replaceSequencerSet` requires `1 <= threshold <= len`).

### 2.5 Prover and witnesses

Every node that may need to prove collects an execution witness per block *before*
canonicalization (`engine.rs:432-439`, `follower.rs:662-678`) into a proof WAL
(`crates/zones/sequencer/src/proofs.rs`). The leader's `SettlementProver` proves batches from
these witnesses; an `rpc_only` follower can run a shadow prover over finalized submissions
(`crates/zones/node/src/shadow_prover.rs`).

---

## 3. How L1 does it, and what transfers

`crates/consensus` (`tempo-consensus`) wires commonware 2026.9.0 as follows (see
`crates/consensus/src/lib.rs:57-166`, `consensus/engine.rs`, `consensus/application/impl.rs`,
`executor/actor.rs`, `alias.rs`, `storage/*`):

| Concern | L1 | Zone PoC |
|---|---|---|
| p2p | `commonware_p2p::authenticated::lookup`, ed25519 identities, peers from `ValidatorConfigV2` | same transport, peers from the manifest (already in `zone-p2p`) |
| Signing scheme | `simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>`, shares from DKG | `simplex::scheme::ed25519::Scheme` (vote key = p2p identity key) |
| Elector | `simplex::elector::Random` (threshold VRF seed) | `simplex::elector::RoundRobin` |
| Epochs | `FixedEpocher(chain_spec.epoch_length)`, DKG outcome in boundary `extra_data`, `epoch::manager` spawns one engine per epoch | one epoch (`FixedEpocher::new(2^40)`), one engine, no DKG |
| Marshal | `marshal::core::Actor` with `Standard<Block>`, `immutable::Archive` for finalizations, `Hybrid` prunable blocks store over reth | identical, `Hybrid` re-pointed at the zone's `BlockchainProvider` |
| Application wrapper | `Marshaled::{Deferred, Immediate(Inline)}`, default `immediate` | `Inline` only (header has no consensus context) |
| Block | `consensus::block::Block` wrapping `SealedOrRecoveredBlock<tempo_primitives::Block>`, digest = EL hash, `CertifiableBlock` from `TempoHeader.consensus_context` | same wrapper type (zones use `TempoPrimitives`/`TempoHeader`), without the `CertifiableBlock` impl |
| Proposal | `Inner::build` → `TempoPayloadAttributes` → executor `build_proposal` → reth FCU+payload → `new_payload` | `ZoneApplication::propose` → `ZonePayloadAttributes` (same as `ZoneEngine::advance` today) → zone executor → reth |
| Verification | `Inner::verify` → header context checks → executor probe `new_payload`, ancestry walk on `SYNCING` | `ZoneApplication::verify` → the follower's validations → executor `new_payload` |
| Finalization | marshal `Update::Block` → executor `new_payload` + FCU(head, safe = finalized) → ack | same, plus witness collection and deposit-queue advance before ack |
| Executor | `executor::actor` (2.7k lines: walks, convergence, scheduling) | a reduced zone executor (§6.5), upgradeable to the L1 actor later |
| Runtime | reth tokio runtime + commonware runtime on a separate thread, linked by handles | same; the existing `zone-p2p` thread becomes the consensus thread |
| Storage dir | `<datadir>/consensus`, `BlobLayout::V0` | `<datadir>/consensus` |
| Follow mode | RPC/gossip-fed marshal with `FinalizationVerifier` | `rpc_only` nodes run the same engine with a verifier-only scheme (§6.8) |

Reusable as-is from `tempo-consensus` (generic, no L1 types): `consensus::digest::Digest`,
`network::SizeLimited`, `utils::OptionFuture`, `metrics::install`, the `Marshaled` enum.
Reusable with a type parameter swap: `consensus::block::Block` (drop the `CertifiableBlock`
impl; keep `validate_body_against_header`), `storage::hybrid::{Hybrid, FinalizedBlocksProvider}`
(already generic over `BlockchainProvider<N>` with `TempoHeader`), `storage::mod` archive
constructors (swap the scheme type). Everything else is L1-coupled: DKG, epoch manager, peer
manager, validator config reads, `TempoPayloadAttributes`, gossip, feed, follow.

---

## 4. Target architecture (to-be)

```text
                        ┌──────────────────────────────── reth tokio runtime ──────────────────────────────┐
  Tempo L1 (finalized)  │  L1Subscriber ──► DepositQueue ──┐                                              │
  ws/http ─────────────►│                  L1BlockTracker ──┤                                              │
                        │                                   │   ZonePayloadBuilder   reth engine tree      │
                        │                                   │   (unchanged)          (new_payload / FCU)   │
                        │                                   │         ▲                     ▲              │
                        │  TempoTransactionPool ◄── tx import│         │ payload builder     │ engine       │
                        │        │  new local txs           │         │ handle              │ handle       │
                        └────────┼──────────────────────────┼─────────┼─────────────────────┼──────────────┘
                                 │                          │         │                     │
                                 ▼                          ▼         │                     │
   ┌────────────────────────── commonware runtime thread (`zone-consensus`) ────────────────┼──────────────┐
   │  lookup::Network (ed25519, manifest peers)                                              │              │
   │   ch0 VOTES ─────────────┐   ch1 CERTIFICATES ───┐  ch2 RESOLVER ─┐   ch3 BROADCASTER   │ ch4 MARSHAL  │
   │                          ▼                       ▼                ▼          ▼          │    ▼         │
   │   simplex::Engine<ed25519::Scheme, RoundRobin> ──reporter──► marshal::core::Actor ◄── buffered ◄──┐   │
   │        ▲ propose/verify (Automaton)                  ▲ Update::{Tip,Block}      broadcast  resolver│   │
   │        │                                              │                                            │   │
   │   Inline<ZoneApplication> ──────────────────────► ZoneExecutor ───────────────────────────────────┘   │
   │        │  (propose: pick anchor, FCU+attrs, resolve, new_payload)                                     │
   │        │  (verify:  anchor/portal-input checks, new_payload)                                          │
   │        │  (finalize: witness WAL, FCU head=safe=finalized, deposit-queue advance, ack)               │
   │        ▼                                                                                              │
   │   ch5 TRANSACTIONS (forward local txs to all quorum peers)                                            │
   │   storage: <datadir>/consensus/{finalizations-by-height, finalized-blocks-prunable, journal}          │
   └───────────────────────────────────────────────────────────────────────────────────────────────────────┘
                                 │ finalized boundary blocks
                                 ▼
   SettlementDuty (owner = participants[batch_index mod n], failover after N L1 blocks)
     └─► ZoneMonitor (prepare BatchData, SPF/Nitro prove, self-sign 1-of-n attestation) ─► submitBatch
     └─► WithdrawalProcessor ─► processWithdrawals
```

Lifecycle of one zone block:

1. Simplex enters view `v`; `RoundRobin` names leader `l = participants[(epoch + v) mod n]`.
2. `l` receives `propose(Context { round, leader, parent: (view, digest) })` through `Inline`.
   `ZoneApplication::propose` reads the parent's post-state cursor (Tempo checkpoint, processed
   deposit number, processed token count), waits until the `DepositQueue` holds the next finalized
   Tempo header, builds `ZonePayloadAttributes` exactly like `ZoneEngine::advance`, asks the
   executor to build on `parent`, and returns the sealed block. The broadcaster ships the block.
3. Every participant receives `verify(context, digest)`. `Inline` fetches the block (buffered
   broadcast or resolver), checks `parent == context.parent` and `height == parent + 1`, then
   `ZoneApplication::verify` re-runs the follower's validations against local L1 observations and
   has the executor execute the block (`new_payload`). It votes `notarize` only on `true`.
4. After `2f+1` notarize votes the view certifies (`certify` is the default `true`) and
   participants broadcast `finalize`; after `2f+1` finalize votes marshal receives the
   finalization, persists block + certificate in its archives, and delivers `Update::Block` to
   the executor in height order.
5. The executor collects the witness, sends FCU with head = safe = finalized = the block,
   advances the `DepositQueue` cursor, and acks. Reth persists lazily, as today.
6. When a finalized block contains `BatchFinalized`, the settlement duty owner's `ZoneMonitor`
   prepares and proves the batch, self-signs the attestation, and submits.

Leader crash: the other participants' `leader_timeout` fires, they broadcast `nullify(v)`, form a
nullification, enter `v+1`, and the next leader proposes on the same certified parent. Nothing
about L1 or the portal is involved.

---

## 5. Key design decisions

### 5.1 Signing scheme and elector: ed25519 + RoundRobin (differs from L1)

L1 needs BLS threshold signatures because its finalization certificates are consumed by followers
and tooling as compact, non-attributable proofs, and the threshold VRF feeds the random elector.
Zones have none of those consumers in the PoC: certificates stay inside the fleet, `n ≤ 8`, and
the portal verifies a separate EIP-712 attestation. Using `commonware_consensus::simplex::scheme::
ed25519::Scheme` means:

- No DKG, no shares, no network identity, no epoch manager. The ed25519 p2p key is also the vote
  key (`Scheme::signer(namespace, participants, private_key)`; see the macro at
  `commonware-cryptography-2026.9.0/src/ed25519/certificate/mod.rs:417-557`).
- Certificates are attributable: a misbehaving sequencer's votes are evidence.
- `RoundRobin` (`commonware-consensus-2026.9.0/src/simplex/elector.rs:240-343`) is deterministic
  and works with any scheme; leader for a round is `permutation[(epoch + term_index) mod n]`.
  `RoundRobin::shuffled(seed)` with the zone namespace as seed avoids a fixed order across zones.

Migration path to L1 parity later: `simplex::scheme::bls12381_multisig` is attributable, compact
enough to verify on-chain, and would let `ZonePortal` accept the Simplex finalization certificate
as the settlement authorization (§13).

### 5.2 Marshal `Standard` variant with the `Inline` wrapper; no consensus context in the header

L1 embeds `TempoConsensusContext { epoch, view, parent_view, proposer }` in `TempoHeader` and
implements `CertifiableBlock`. The zone SPF constructs block environments with
`consensus_context: None` (`crates/zones/spf/src/execution/evm.rs:205, 230`), and the stateless
prover recomputes the header hash. A zone header with a context would not prove. Options:

- (chosen) Use `marshal::standard::Inline` (`commonware-consensus-2026.9.0/src/marshal/standard/
  inline.rs`), which only needs `crate::Block` and verifies fully before the notarize vote.
  This also matches L1's default `--consensus.verification-mode immediate`.
- (later) Extend `ZoneBlock` in the SPF to carry `consensus_context`, then switch to `Deferred`.

Consequence: the proposer identity is not committed in the block. The beneficiary rule (§6.3)
substitutes for it in verification.

### 5.3 Fault model and fleet size

commonware ships `N3f1` and `N5f1` only (`commonware-utils-2026.9.0/src/faults.rs`), and the
ed25519 scheme is instantiated with `N3f1`. With `n = 3`, `f = 0` and quorum = 3: one crashed
node halts consensus. Options:

| Option | Nodes | Tolerates | Notes |
|---|---|---|---|
| A (recommended for the PoC) | 4 quorum members | 1 Byzantine | Library default, identical to L1 semantics, zero custom crypto |
| B | 3 quorum members | 1 crash, 0 Byzantine | Custom `Faults` type (`max_faults = (n-1)/2`) and a re-instantiation of `impl_certificate_ed25519!` in-repo. Majority quorums intersect in one honest node, which is sufficient for Simplex safety when nodes never equivocate. A compromised node could fork the zone. The prover still prevents invalid state from settling. |
| C | 3 members, 1 is a non-voting `rpc_only` | 0 | Same as today's 3-node topology but with no fault tolerance; pointless |

Recommendation: build the PoC with option A and run four-node clusters in tests. Keep option B as
a one-file follow-up if the operator wants three machines; it should be a conscious trust
decision, not a default.

### 5.4 Static participant set, single epoch

The manifest's quorum nodes are the participants. Membership changes require a coordinated restart
with a new manifest at a known height; this is already the operational model for membership today
(`setSequencerSet` plus manifest edit). `FixedEpocher::new(NZU64!(1 << 40))` gives one epoch
containing every height the zone will ever reach, so marshal's epoch-boundary re-proposal and the
simplex `Floor` logic are never exercised beyond epoch 0.

Later (§13): read `SequencerSetUpdated` from the portal at a batch boundary and rotate epochs, as
L1 reads `ValidatorConfigV2` at DKG boundaries.

### 5.5 Block production stays L1-anchored

A full zone block imports exactly one finalized Tempo header; a checkpoint-only block imports a
range. The protocol (and the SPF) does not allow a zone block without a Tempo import, so a view
whose leader has no new finalized anchor cannot produce a block. `propose` therefore waits for the
next anchor (bounded by `leader_timeout`) and returns `None` if none arrives; Simplex treats
`None` as a skipped slot and nullifies the view. During an L1 finality stall this produces one
nullification per `leader_timeout` and no blocks, which is the correct outcome.

The `DepositQueue` is consumed **only when a block finalizes**, not when it is proposed or
verified. A proposal that is nullified must leave the queue untouched; the next proposer selects
its anchor relative to the parent's post-state, not the queue front (§6.4).

### 5.6 Settlement with a 1-of-n portal threshold and rotating duty

- Portal configuration: `setSequencerSet(all individual addresses, threshold = 1)`. `submitBatch`
  then accepts one self-signed attestation from any active sequencer. This is the existing
  "legacy 1-of-1" path in `BatchSubmitter::submit_batch` (`settlement.rs:448-470`), so the
  `SettlementManager`, the settlement P2P channels, `build_settlement_attestation` and the
  follower's proposal signing are removed.
- Duty rotation: `owner(batch) = participants[withdrawal_batch_index mod n]`, using the same
  `ordered::Set` order the scheme uses. If the portal `zoneHeight` has not advanced past the
  boundary within `settlement_failover_l1_blocks` (default 60 Tempo blocks, ≈30 s) after the
  boundary finalized locally, every other node becomes eligible and submits. Duplicate
  submissions revert on `prevBlockHash`; the loser rebuilds from portal state, which the monitor
  already does (`monitor.rs:688-760`).
- Every quorum node runs the `ZoneMonitor`, the prover, and the withdrawal processor, but only
  the current owner (or a failover) sends L1 transactions. Each node has its own proof WAL, so
  any node can prove any batch.
- The portal `leader*` fields become vestigial. Operational note: `setSequencerSet` still rejects
  removing the address stored in `leader` (`ActiveLeaderRemoved`), so an admin must `setLeader`
  to a remaining member before removing that address. No contract change for the PoC.

### 5.7 Executor: a reduced zone executor first

The L1 executor actor handles ancestry walks, convergence of the EL head to the consensus
pending head, build arbitration, and backfill, with a 1.3k-line test harness. Its public seams
(`ExecutionLayer`, `Marshal` traits in `crates/consensus/src/executor/mod.rs:44-141`) name
`TempoPayloadAttributes` and `TempoExecutionData`; zones use `ZonePayloadAttributes` with the same
`TempoExecutionData`/`TempoBuiltPayload`. For the PoC, write a reduced executor (§6.5) with the
same contract (one engine call in flight, finalized-before-ack, backfill on startup), then
evaluate generalizing the L1 actor over the attributes type as the production path.

### 5.8 Networking and storage placement

The `zone-p2p` runtime already owns a commonware tokio runtime with a storage directory. Simplex,
marshal, the buffered broadcast engine and the resolver must run inside a commonware `Context`
(they need `Spawner + Clock + Storage + Metrics`), so they run on that thread. The reth node
exposes `ConsensusEngineHandle`, `PayloadBuilderHandle`, the provider and the pool; these are
`Send + 'static` handles that L1 already calls from the commonware runtime
(`crates/consensus/src/executor/mod.rs:143-237`).

---

## 6. Component specifications

### 6.1 New crate: `crates/zones/consensus` (`zone-consensus`)

```
crates/zones/consensus/src/
  lib.rs            // run_zone_consensus(context, config, handles) entry point; channel ids
  config.rs         // ZoneConsensusConfig (timing, datadir, participants, local keys)
  digest.rs         // copy of crates/consensus/src/consensus/digest.rs
  block.rs          // copy of crates/consensus/src/consensus/block.rs minus CertifiableBlock
  application.rs    // ZoneApplication: Application<E> impl (propose/verify), Reporter impl
  executor/         // ZoneExecutor actor + Mailbox + ExecutionLayer/Marshal traits
  storage/          // archives (ed25519 Finalization), Hybrid blocks store over the zone provider
  peers.rs          // StaticPeerProvider: commonware_p2p::Provider over the manifest
  settlement_duty.rs// owner/failover rule shared with zone-sequencer
  metrics.rs        // install() copied from crates/consensus/src/metrics.rs
```

Dependencies: `commonware-{consensus,cryptography,codec,p2p,broadcast,runtime(external),storage,
utils,parallel,actor}`, `zone-p2p`, `zone-l1`, `zone-payload`, `zone-sequencer` (proof collector
handle), `tempo-primitives`, `tempo-payload-types`, `tempo-evm` (`validate_body_against_header`),
`reth-node-api`, `reth-payload-builder`, `reth-provider`, `reth-storage-api`.

Core type aliases (verified against commonware 2026.9.0 signatures; see Appendix A):

```rust
pub type Scheme    = commonware_consensus::simplex::scheme::ed25519::Scheme;
pub type PublicKey = commonware_cryptography::ed25519::PublicKey;
pub type Provider  = commonware_cryptography::certificate::ConstantProvider<Scheme, Epoch>;
pub type Epocher   = commonware_consensus::types::FixedEpocher;           // new(NZU64!(1 << 40))
pub type Finalization = commonware_consensus::simplex::types::Finalization<Scheme, Digest>;
pub type Certificates<E> = commonware_storage::archive::immutable::Archive<E, Digest, Finalization>;
pub type Marshal<E>  = commonware_consensus::marshal::core::Actor<
    E, Standard<Block>, Provider, Certificates<E>, Hybrid<E, ZoneProvider>, Epocher, Sequential, Exact>;
pub type MarshalMailbox = commonware_consensus::marshal::core::Mailbox<Scheme, Standard<Block>>;
pub type Application<E> = commonware_consensus::marshal::standard::Inline<E, Scheme, ZoneApplication, Block, Epocher>;
```

`ZoneProvider` is the zone node's `BlockchainProvider<NodeTypesWithDBAdapter<ZoneNode, DatabaseEnv>>`
(the L1 `Hybrid` is generic over `BlockchainProvider<N>` where `N::Primitives` gives
`tempo_primitives::Block` and `TempoHeader`; `ZoneNode` sets `Primitives = TempoPrimitives`, so the
impl at `crates/consensus/src/storage/hybrid/mod.rs:158-230` applies after copying).

### 6.2 Block and Digest

Copy `Digest` verbatim. Copy `Block` and keep:

- `try_from_execution_block` with `validate_body_against_header` and the
  `block_access_list_hash().is_none()` requirement (zone blocks never carry a BAL).
- codec = raw RLP of the sealed block, `Read::Cfg = ()`, digest = EL block hash,
  `Heightable`, `Committable`, `Digestible`, `commonware_consensus::Block::parent`.

Drop the `CertifiableBlock` impl. Add a zone-specific invariant in the validating constructor:
`header.consensus_context.is_none()` and `header.extra_data.is_empty()`; blocks violating either
are unprovable and must be rejected before voting.

### 6.3 `ZoneApplication` (propose / verify)

```rust
pub struct ZoneApplication {
    local: PublicKey,
    executor: executor::Mailbox,
    deposit_queue: DepositQueue,
    l1_block_tracker: L1BlockTracker,
    encryption_keys: EncryptionKeyRing,
    chain_spec: Arc<ZoneChainSpec>,
    portal_address: Address,
    beneficiary: Address,                 // shared sequencer address (see note)
    expected_beneficiary: Arc<dyn Fn(&PublicKey) -> Option<Address>>, // manifest lookup
    proposal_anchor_wait: Duration,       // < leader_timeout
}

impl<E: Rng + Spawner + Metrics + Clock> commonware_consensus::Application<E> for ZoneApplication {
    type SigningScheme = Scheme;
    type Context = simplex::types::Context<Digest, PublicKey>;
    type Block = Block;
    type Input = ();
    async fn propose(&mut self, (rt, ctx): (E, Context), mut ancestry: impl Ancestry<Block>, (): ()) -> Option<Block>;
    async fn verify(&mut self, (rt, ctx): (E, Context), mut ancestry: impl Ancestry<Block>) -> bool;
}
```

**propose** (leader):

1. `parent = ancestry.next().await?` (marshal supplies it; it is certified or locally verified).
2. Ensure the parent is executed: `executor.ensure_executed(parent)` (a `new_payload` of the
   parent if reth reports it unknown; the executor's ancestry walk handles deeper gaps).
3. Read the parent's post-state cursor through the provider at `parent.hash()`:
   `tempo_num_hash()` from `TempoState` (as `follower.rs:577-581` does), plus
   `lastProcessedDepositNumber` and `lastProcessedEnabledTokenCount` from `ZoneInbox` (the reads
   `read_zone_block_snapshot` performs today, `settlement.rs:1686`).
4. Select the import with the **cursor-relative** queue API (§6.4):
   `deposit_queue.next_import_after(cursor, chain_spec, l1_block_tracker, now)`. If nothing is
   available, await `deposit_queue.notified()` with `proposal_anchor_wait` and retry once; else
   return `None` (skip the slot). Also return `None` while `l1_block_tracker.portal_paused()`.
5. Build `ZonePayloadAttributes` exactly as `ZoneEngine::advance` (`engine.rs:344-400`):
   timestamp `max(l1_ts, wall_clock, parent_ts)`, `suggested_fee_recipient = beneficiary`,
   `tempo_import` = `Full(prepare_many(...))` or `CheckpointOnly(headers)`.
6. `executor.build(parent_digest, attrs).await` → `TempoBuiltPayload` → `Block::from_execution_block_unchecked_with_encoded_cache`.
7. Return `Some(block)`. Cancellation-safe: nothing is consumed from the queue.

**verify** (every participant), modeled on `FollowerBlockSync::import_peer_block`
(`follower.rs:518-718`) with the queue mutations removed. Return `false` only for permanent
invalidity; keep the future pending while evidence may still arrive:

| Check | Source today | Verdict on failure |
|---|---|---|
| `block.header.consensus_context.is_none()`, `extra_data.is_empty()`, no BAL, body matches header | new + `Block::try_from_execution_block` | `false` |
| Decoded opening tx is `advanceTempo` or `advanceTempoHeaders` (`decode_advance_tempo`) | `follower.rs` | `false` |
| Imported header range is contiguous from the parent's checkpoint (`validate_l1_checkpoint_range`) | `follower.rs:882-913` | `false` |
| Final imported anchor was observed by the local L1 subscriber (`l1_block_tracker.wait_for(anchor)`) | `follower.rs:804-825` | **pending** until observed (no timeout; the view times out instead) |
| Full block: deposits and enabled tokens equal the locally observed portal events after the parent cursor (`validate_advance_tempo_inputs`) | `follower.rs:764-802` | `false` |
| `header.beneficiary == expected_beneficiary(ctx.leader)` | new | `false` |
| `header.timestamp_millis <= now + skew` | `validate_block_timestamp` | **wait** until `timestamp_millis` (L1 behavior, `impl.rs` `wait_until_timestamp`) then continue |
| Execution: `executor.verify(block)` → `new_payload` VALID | `follower.rs:652-658` | `INVALID` → `false`; `SYNCING` → executor fetches parents via marshal and retries (pending) |

Beneficiary note: in production every quorum node holds the same shared sequencer key, so
`expected_beneficiary` is a constant. The test harness deliberately gives each node a distinct
"shared" signer to identify producers (`tests/it/utils.rs:4200-4207`); support that with an
optional `beneficiary` field per manifest node, defaulting to the shared address.

**Reporter**: `ZoneApplication` also implements `Reporter<Activity = marshal::Update<Block>>` to
observe tips for metrics, as L1's `Inner` does; the executor is the reporter that acks.

Determinism review of `verify`: every `false` above depends only on the block, the parent's
post-state, and finalized L1 data that all honest nodes eventually observe identically (Tempo
finality is deterministic; the subscriber rejects conflicting finalized headers,
`queue.rs:72-114`). The only local inputs are "have I observed this anchor yet" and wall-clock,
and both are handled by waiting, never by rejecting.

### 6.4 `DepositQueue` changes (`crates/zones/l1/src/queue.rs`)

The queue remains append-only and finalized-driven. Changes:

1. **Cursor-relative selection.** Add
   `fn next_import_after(&self, cursor: PortalWorkCursor, max_checkpoint_headers) -> Option<AvailableTempoImport>`
   where `PortalWorkCursor { tempo_checkpoint: NumHash, processed_deposit_number: u64,
   processed_token_count: u64 }`. It locates the pending entry whose number is
   `cursor.tempo_checkpoint.number + 1` (hash-linked), applies `tempo_import_decision` (moved from
   `engine.rs:568-633` into `zone-l1` or `zone-payload` so both propose and tests share it), and,
   for a full import, aggregates the portal events of every retained entry with number
   ≤ anchor whose deposit index is `> processed_deposit_number` and whose token enablements are
   beyond `processed_token_count`. This replaces the mutable `deferred` state as the source of
   "work owed by the next full block" for proposals; `DeferredPortalWork` remains for restart
   reconstruction and finalized bookkeeping.
2. **Finalization-driven advance.** `confirm_operational_through` and `defer_through` are called
   by the executor on `Update::Block`, never by propose/verify. Both are already idempotent and
   tolerant of stale entries (`queue.rs:303-333`). Entries now live until finalization, a few
   views longer than today; `MAX_L1_LOOKAHEAD_BLOCKS = 7_200` still bounds memory.
3. **Deposit numbering in events.** `L1PortalEvents` must expose each deposit's queue index so
   the cursor filter in (1) is exact. Check `crates/zones/l1/src/event.rs` and `deposit.rs`; the
   portal emits `DepositMade` with the deposit number, so this is bookkeeping, not a protocol change.

### 6.5 `ZoneExecutor`

A single actor on the commonware runtime owning the reth engine handle and payload builder handle.
Invariant: one engine call in flight at a time (reth's engine is a single consumer anyway and L1
relies on the same rule).

```rust
pub(crate) enum Command {
    EnsureExecuted { digest: Digest, response: oneshot::Sender<eyre::Result<()>> },
    Build { parent: Digest, attrs: ZonePayloadAttributes, response: oneshot::Sender<eyre::Result<TempoBuiltPayload>> },
    Verify { block: Arc<Block>, response: oneshot::Sender<eyre::Result<Option<Duration>>> }, // Some = VALID, None = INVALID, Err = abstain
    Finalize(marshal::Update<Block>),   // via Reporter impl on the Mailbox
}
```

State: `finalized: (Height, Digest)`, `delivered_floor: Height`, `pending_finalizations:
VecDeque<(Arc<Block>, Exact)>`, `executed: LruSet<Digest>` (digests reth has accepted),
`in_flight: Option<ExecutionTask>`.

Behaviors:

- **Startup.** Wait for `fork_choice_updated(current EL state)` to be VALID (reth returns
  `SYNCING` during startup). Then backfill from EL finalized + 1 to marshal's floor: for each
  height, `marshal.get_block(height)` → `new_payload` → FCU every 8 blocks and at the end
  (`backfill_to_finalized_floor`, `executor/actor.rs:1093-1151`).
- **EnsureExecuted / Verify.** `new_payload(block)`. `VALID` → done. `SYNCING` → the parent is
  unknown to reth: fetch it from reth (`find_sealed_or_recovered_block`), else marshal
  `get_block(digest)`, else `marshal.subscribe_by_digest(digest, round)`; execute parents oldest
  first, then retry. Depth is bounded by `view_retention` because any parent older than the
  finalized tip is delivered by the finalization pipeline instead. `INVALID` → `None`.
- **Build.** `EnsureExecuted(parent)`, then
  `fork_choice_updated(ForkchoiceState { head: parent, safe: finalized, finalized }, Some(attrs))`
  → `payload_id` → `payload_builder.resolve_kind(id, WaitForPending)` →
  `new_payload(built)` must be VALID → return. The zone payload builder freezes its payload
  (`builder.rs:410-414`), so one resolve returns the deterministic block.
- **Finalize.** For each delivered block in order: `EnsureExecuted`; collect the witness
  (`proof_collector.collect_and_persist(number, hash)`) exactly as the follower does before its
  FCU (`follower.rs:662-678`); `fork_choice_updated(same_hash(hash), None)` must be VALID;
  `l1_block_tracker.prune_through(anchor)`, `deposit_queue.{defer_through|confirm_operational_through}(anchor)`
  (`follower.rs:697-713`); then `ack`. Never move `finalized` backwards; a conflicting canonical
  hash at a finalized height is fatal (as in L1's `is_stale_forkchoice`).
- **Heartbeat.** Re-send the last FCU every `fcu_heartbeat_interval` (L1: 5 min) when idle.

What is intentionally dropped versus L1: build arbitration (one proposal at a time suffices for
the PoC), convergence to the pending head (zones only move the EL head when building or
finalizing), and the metrics set. These are the first things to pull back from
`executor/actor.rs` if the PoC shows gaps.

### 6.6 Marshal and storage wiring

Mirror `crates/consensus/src/alias.rs:122-247` and `storage/mod.rs`:

- `certificates = immutable::Archive<_, Digest, Finalization<Scheme, Digest>>` under
  `engine-finalizations-by-height-*` with `Scheme::certificate_codec_config_unbounded()`.
- `blocks = Hybrid::new(prunable::Archive<TwoCap, _, Digest, Block>, zone_provider, retention)`
  (`storage/hybrid/mod.rs`), 4096 items per section, zstd 3, retention `finalized_blocks_retention`
  (L1 default 64 800).
- `start`: if the certificates archive is empty, require the EL to be at the zone genesis and use
  `Start::Genesis(Block::from_execution_block_unchecked(genesis))`; otherwise `Start::Floor(last
  finalization)`. `finalized_floor` and `finalized_tip` seed the executor.
- `marshal::Config { provider: ConstantProvider::new(scheme), epocher, start, partition_prefix:
  "engine", mailbox_size, view_retention: views_to_track * 10, prunable_items_per_section,
  page_cache, replay_buffer 8 MiB, key/value write buffers 1 MiB, block_codec_config: (),
  max_repair 20, max_pending_acks 1, strategy: Sequential }`.
- Reporter fan-out: `Reporters::from((inline_application.clone(), executor_mailbox))`.
- Broadcast: `buffered::Engine::new(ctx, buffered::Config { public_key, mailbox_size, deque_size
  10, peer_provider: StaticPeerProvider, priority: true, codec_config: () })`.
- Resolver: `marshal::resolver::p2p::init(ctx, Config { public_key, peer_provider, blocker:
  oracle, mailbox_size, timeout 2 s, fetch_retry_timeout 100 ms, priority_* false })`.
- Simplex: `simplex::Engine::new(ctx, simplex::Config { scheme, elector:
  RoundRobin::shuffled(namespace), blocker: oracle, automaton: inline.clone(), relay:
  inline.clone(), reporter: marshal_mailbox, track_historical_votes: true, strategy: Sequential,
  partition: "engine_simplex_epoch_0", mailbox_size, epoch: Epoch::new(0), floor:
  Floor::Genesis(genesis_digest) | Floor::Finalized(tip_cert), replay_buffer, write_buffer,
  page_cache, leader_timeout, certification_timeout, timeout_retry, view_retention, skip:
  SkipPolicy::Enabled { timeout, budget: SkipBudget::Participants }, fetch_timeout, forward:
  ForwardPolicy::Disabled })`.
- Start order as L1 (`engine.rs:535-586`): marshal, executor, broadcast, resolver, simplex;
  `Handle::select` so one actor's exit stops all.

### 6.7 `zone-p2p` changes

- Channels: replace `BLOCK_CHANNEL`, `BACKFILL_*`, `SETTLEMENT_*` with `VOTES = 0`,
  `CERTIFICATES = 1`, `RESOLVER = 2`, `BROADCASTER = 3`, `MARSHAL = 4`, `TRANSACTIONS = 5`.
  Quotas from `crates/consensus/src/config.rs:40-48` (marshal rate = `backfill_frequency`
  8/s), transaction quota unchanged. Wrap each channel in `SizeLimited`.
- Delete `backfill.rs`, `capabilities.rs`, `protocol.rs` (block framing), the leadership gates in
  `routing.rs`, and `P2pCommand::{BroadcastBlock, BroadcastSettlementProposal,
  SendSettlementSignature}`. Keep `ForwardTransaction`, now unconditionally sent to all other
  quorum peers (`transaction_forwarding_status` goes away). Keep `P2pEvent::TransactionReceived`.
- `P2pConfig` gains `storage_directory` (already present) pointed at `<datadir>/consensus`,
  worker threads (L1 default 3), and exposes the `lookup::Oracle` to `zone-consensus` as
  `Blocker`.
- `StaticPeerProvider`: `commonware_p2p::Provider` returning the manifest's quorum nodes as
  `primary` and `rpc_only` nodes as `secondary` at peer-set id 0, with a `subscribe()` that never
  fires. The oracle is already tracked with these sets (`network.rs:141-174`).
- Manifest schema: drop `leader_ed25519_public_key`, `historical_leaders`, `forced_recovery`;
  add optional `[consensus]` with the timing table of §7 and optional `beneficiary` per node.
  `MIN_QUORUM_NODES` becomes 4 under option A. `validate_node` and `membership_digest` stay.
- The commonware runtime thread hosts both the network and `zone_consensus::run(...)`; the
  `spawn_p2p` result returns the context pieces consensus needs (network channels, oracle, context
  child) instead of the block/backfill ports.

### 6.8 Node wiring (`crates/zones/node/src/node.rs`) and deletions

Replace the `P2PRuntime` branch of `launch_add_ons` (`node.rs:639-953`):

- Keep: zone-id validation, enabled-token and encryption-key seeding, portal pause watcher,
  `L1Subscriber` (with `leadership_sink: None`), redacted RPC, proof collector and prover.
- Remove: `seed_leadership_schedule`, `install_manifest_forced_recovery`,
  `ScheduleLeadershipSink`, `run_role_controller`, `EventSinks` routers, `serve_backfill_requests`,
  the persisted-block broadcaster, `AttestationContext`, `SettlementManager`,
  `validate_registered_sequencer_set`'s threshold reachability (replaced by: every quorum node's
  individual address is an active sequencer and `sequencerThreshold == 1`).
- Add: `zone_consensus::run(ZoneConsensusConfig { local_ed25519_key, participants, namespace,
  timing, datadir }, ZoneHandles { engine_handle, payload_builder, provider, deposit_queue,
  l1_block_tracker, encryption_keys, proof_collector, chain_spec, portal_address, beneficiary })`
  on the commonware thread; a transaction-import task (`insert_forwarded_transactions`, kept
  from `tx_forwarding.rs`) and a forward task on the reth runtime for every quorum node.
- Settlement: spawn `spawn_zone_sequencer(..., settlements: None, duty: SettlementDuty)` on every
  quorum node (§6.9) for the process lifetime; no generation switching.
- `rpc_only` nodes: run the same consensus stack with `Scheme::verifier(namespace, participants)`
  (the simplex engine runs passively, receives votes/certificates on the channels, and marshal
  finalizes). They do not forward transactions to themselves and never hold the shared key.
  Their executor finalizes without witness collection unless shadow proving is configured.

Files to delete: `node/src/role.rs`, `node/src/follower.rs`, `node/src/replication.rs`,
`node/src/settlement_attestation.rs`, `engine.rs`'s `ProductionPermit`/`EngineExit`/`run_until`
(the legacy single-sequencer `ZoneEngine::run` path can remain for `--sequencer` mode or be
replaced by a one-node Simplex instance; see §12), `sequencer/src/settlement_manager.rs`,
`sequencer/src/attestation.rs` (keep the `SettlementAttestation` type used by `submit_batch`),
`p2p/src/{backfill,capabilities,protocol}.rs`, `l1`'s `LeadershipSink`/`LeaderTransition` plumbing
(the subscriber must still *decode* `LeaderUpdated` without erroring).

### 6.9 Settlement duty (`zone-sequencer`)

```rust
pub struct SettlementDuty { participants: Vec<Address>, local: Address, failover: u64 /* L1 blocks */ }
impl SettlementDuty {
    pub fn owner(&self, withdrawal_batch_index: u64) -> Address;
    pub fn may_submit(&self, batch: &BatchData, portal: &PortalZoneAnchor, now_l1: u64, boundary_seen_at_l1: u64) -> bool {
        self.owner(batch.withdrawal_batch_index) == self.local
            || (portal.block_number < batch.zone_height && now_l1 >= boundary_seen_at_l1 + self.failover)
    }
}
```

`ZoneMonitor` changes (`monitor.rs`):

- `prepare_artifacts` always uses `prepare_certificate = None` (self-sign in `submit_batch`).
- `submit_ready_batch` consults `duty.may_submit`; when false it parks the ready batch and
  re-checks on each L1 block or portal `BatchSubmitted` observation; when the portal advances past
  the batch, it drops the batch and advances the cursor from `resolve_portal_zone_anchor`.
- The withdrawal processor uses the same owner rule per `BatchSubmitted` slot.
- `pinned_sequencer_set_version` is kept so a `setSequencerSet` during operation fails loudly.

### 6.10 Prover and witness integration

Unchanged in substance: the executor calls `collect_and_persist` for every finalized block before
its FCU, so every quorum node has a complete proof WAL and can prove any batch. The witness
envelope on the wire (`EncodedBlock::WITNESS_PREFIX`) disappears with the custom block protocol;
marshal backfill ships bare blocks, and a node that backfills finalized blocks collects witnesses
locally during its executor backfill (today's `collect_canonical_tail` path).

### 6.11 CLI (`crates/zones/node/src/cli.rs`)

Keep `--sequencer.manifest`, `--p2p.key`, `--secp256k1.key`, `--p2p.listen`,
`--p2p.bypass-ip-check`, `--sequencer-key-file`, prover flags. Remove `--sequencer.role`.
Add a `--consensus.*` subset mirroring L1 names and defaults (`crates/consensus/src/args.rs`):
`wait-for-proposal` (leader_timeout), `wait-for-notarizations` (certification_timeout),
`wait-to-rebroadcast-nullify`, `inactive-time-before-leader-skip`, `wait-for-peer-response`,
`views-to-track`, `mailbox-size`, `deque-size`, `worker-threads`, `fcu-heartbeat-interval`,
`finalized-blocks-retention`, `datadir`, plus zone-specific `proposal-anchor-wait` and
`settlement-failover-l1-blocks`. Manifest `[consensus]` values are defaults; flags override.

### 6.12 RPC and metrics

`SequencerRpcContext` (`node/src/rpc.rs:87-108`) loses `schedule`, `status`, `peer_tips`,
`relayer`; the status method reports consensus view/round, finalized height, participant set,
local role (`signer`/`verifier`), settlement-duty owner for the next batch, and marshal floor.
Metrics to copy from L1: `finalization_lag`, `finalized_blocks_proposed_by_self`,
`dropped_oversized_messages{channel}`, plus commonware's own simplex/marshal metrics exposed via
`metrics::install` on a `--consensus.metrics-address`.

---

## 7. Timing parameters

Tempo finalizes a block roughly every 500 ms, and a zone block needs a new finalized anchor, so a
zone view normally lasts one L1 block. L1 values are from `crates/consensus/src/args.rs`.

| Parameter | L1 default | Zone PoC default | Why |
|---|---|---|---|
| `leader_timeout` | 1 200 ms | 2 500 ms | must cover anchor arrival jitter (`proposal_anchor_wait` 1 500 ms) plus build (~100 ms) plus propagation |
| `certification_timeout` | 2 s | 4 s | > leader_timeout (asserted by `Config::assert`) |
| `timeout_retry` | 10 s | 10 s | nullify rebroadcast |
| skip timeout | 11.2 s | 12 s | > certification_timeout and > timeout_retry |
| `fetch_timeout` | 2 s | 2 s | |
| `view_retention` | 256 views (marshal ×10) | same | |
| `proposal_anchor_wait` | n/a | 1 500 ms | how long `propose` waits for the next finalized anchor before skipping |
| `fcu_heartbeat_interval` | 5 min | 5 min | |
| `finalized_blocks_retention` | 64 800 | 64 800 | ~9 h of blocks at 500 ms |
| `settlement_failover_l1_blocks` | n/a | 60 | ≈30 s before another node submits |

During catch-up (many queued anchors, checkpoint-only blocks of up to 1 024 headers) views are
not gated by L1 and run at network plus execution speed, as L1 does.

---

## 8. Failure scenarios

| Scenario | Behavior |
|---|---|
| Leader crashes mid-view | Others time out (`leader_timeout`), nullify, next leader proposes on the certified parent. Downtime ≈ 2.5 s. No operator action. |
| Leader crashes after notarization, before finalization | The notarized block is forced-included: the next leader builds on it (`simplex/mod.rs` "Forced Inclusion"); every honest node already executed it in `verify`. |
| One of four nodes down for hours | Quorum 3 continues. On return the node's marshal resolver backfills certificates and blocks; the executor replays them into reth. |
| Node loses its disk | Restart with the manifest; marshal starts at `Start::Genesis`, backfills every finalized block from peers, executor rebuilds reth state. Witnesses for unsettled blocks are recollected during backfill. |
| Two of four nodes down | Consensus halts (no quorum). Nothing is lost; resumes when one returns. (Option B of §5.3 changes this trade-off.) |
| L1 finality stalls | `propose` returns `None`; one nullification per view; no zone blocks; settlement waits. Resumes automatically. |
| Node observes the finalized anchor late | Its `verify` stays pending; if it is not needed for quorum nothing happens; if it is, the view times out and the same block is re-proposed or forced-included later. |
| Portal paused | Leaders return `None` from `propose` until the pause clears; verifiers do not check the pause (today's semantics). |
| Settlement owner crashes before `submitBatch` | After `settlement_failover_l1_blocks` any node submits. Duplicate submissions revert on `prevBlockHash`. |
| Prover unavailable on the owner | Owner cannot settle; failover node proves from its own WAL and submits. |
| Byzantine sequencer (option A) | Cannot fork the finalized chain or forge a block; its invalid proposals fail `verify`; its L1 submissions still need a valid proof. |

---

## 9. Trust and safety notes

- Validity of zone state transitions is guaranteed by the SPF and Nitro verifier, not by
  consensus. Consensus provides a single, durable, replicated ordering so that (a) no two nodes
  settle different chains, (b) a crash never loses blocks behind a submitted batch, and
  (c) leadership rotates without L1 transactions.
- The shared sequencer key (ECIES) must be on every quorum node, as today, because any node may
  propose and must decrypt deposits. `rpc_only` nodes never hold it.
- Without a consensus context in the header, a block does not prove which node built it. The
  beneficiary check in `verify` plus attributable ed25519 votes give the fleet that evidence
  locally, which is what the current design offers too (`beneficiary == sequencer`).
- Threshold 1 means a single compromised individual key can submit a batch, but only a batch the
  verifier accepts for the chain the fleet finalized (the portal's `prevBlockHash` and the proof
  bind it). That is the same exposure a 2-of-3 fleet had to its leader plus one follower.

---

## 10. Work breakdown (PoC)

Estimates are for one engineer familiar with the codebase. "Spike" below is the standalone
type-check in Appendix A.

| # | Phase | Work | Est. |
|---|---|---|---|
| 0 | Spike | Standalone crate wiring `ed25519::Scheme` + `RoundRobin` + `Inline` + `marshal::core::Actor` + `simplex::Engine` with a mock block (done, see Appendix A) | 0.5 d |
| 1 | `zone-consensus` skeleton | Crate, `Digest`, `Block` (copied, `CertifiableBlock` dropped, zone invariants added), config, metrics install | 1.5 d |
| 2 | P2P | Channel re-registration, `SizeLimited`, `StaticPeerProvider`, manifest schema change, delete block/backfill/settlement protocols, run consensus on the p2p thread | 2 d |
| 3 | Deposit queue | `PortalWorkCursor`, `next_import_after`, move `tempo_import_decision`, deposit-index bookkeeping in `L1PortalEvents` | 1.5 d |
| 4 | Application | `ZoneApplication::{propose, verify}` reusing follower validators; beneficiary rule; tests with the `L1Fixture` | 3 d |
| 5 | Executor | Reduced `ZoneExecutor` (ensure/build/verify/finalize/backfill/heartbeat), witness + queue advance on finalization | 3 d |
| 6 | Marshal/storage | Archives, `Hybrid` over the zone provider, start/floor logic, restart | 2 d |
| 7 | Node wiring | Replace role controller in `node.rs`, delete dead modules, CLI flags, status RPC | 2 d |
| 8 | Settlement duty | `SettlementDuty`, monitor/withdrawal-processor gating, portal threshold-1 provisioning in `dev.rs` and `just deploy-zone` | 1.5 d |
| 9 | Tests | Four-node harness, crash/restart/disk-loss, settlement on in-process L1, chaos proxies | 4 d |
| 10 | Docs | Update `zones/specs/spec.md` §Sequencer Operations, `invariants.md`, `ZONES.md` | 1 d |

Total ≈ 22 engineer-days. Phases 1–3 can proceed in parallel with 4–6.

Build order that keeps the tree compiling: 1 → 2 (behind a `simplex` cargo feature in
`zone-p2p`/`zone-node` so the old protocol still builds) → 3 → 5 → 6 → 4 → 7 → 8 → 9. Remove the
feature flag and dead code at the end of 7.

---

## 11. Test plan

Reuse `crates/zones/node/tests/it/utils.rs` and `utils/network.rs`:

- `start_local_p2p_cluster` (`utils.rs:4184-4290`) becomes a four-node cluster with manifests
  lacking a leader; `P2pCluster::publish_transition` is removed; `inject_block` /
  `inject_block_observed_by` / `wait_all_at` / `assert_same_block` are kept.
- **Liveness and rotation:** inject N anchors, assert every node reaches height N with identical
  hashes and that beneficiaries (per-node manifest beneficiary) rotate round-robin.
- **Leader crash:** `cluster.nodes.remove(i).crash()` while it is the next leader; assert the
  remaining three continue within `leader_timeout + margin` and the crashed node's last notarized
  block is included or nullified consistently.
- **Restart and disk loss:** stop a node, inject 50 anchors, restart it (and a variant with the
  datadir wiped); assert it converges and its marshal archive contains every finalized block.
- **Late anchor observation:** `inject_block_observed_by(.., &[0, 1, 2])`; node 3 must stay
  pending in `verify`, not reject; deliver the anchor; node 3 imports.
- **Invalid proposal:** a test hook that makes one node propose a block with a wrong
  beneficiary or a mismatched deposit list; assert the view is nullified and the proposer's
  block never finalizes.
- **Deposit-queue semantics:** nullified views do not consume anchors; finalized blocks advance
  the queue exactly once (port `handoff_e2e.rs` assertions on `TempoState`).
- **Settlement:** in-process L1 (`l1_e2e.rs` path) with a portal created with four sequencers and
  `threshold = 1`; assert `submitBatch` by the duty owner, then crash the owner before a boundary
  and assert failover submission after `settlement_failover_l1_blocks`.
- **Chaos:** adapt `network_chaos_p2p_e2e.rs` partitions and latency to the new channels.
- **Contracts:** no Solidity changes; add a Foundry test documenting the intended
  `setSequencerSet(4 members, threshold 1)` configuration if desired.

---

## 12. Open questions for the user

1. **Fleet size.** Four nodes with the library fault model (recommended) or three nodes with a
   custom crash-only model (§5.3)?
2. **Single-sequencer mode.** Keep the legacy `--sequencer` path (`ZoneEngine::run` with no P2P)
   for dev and small deployments, or run a one-participant Simplex instance everywhere
   (`N3f1` with `n = 1` works, quorum 1) so there is one code path? Recommendation: one code path,
   with `tempo-zone dev` writing a one-node manifest.
3. **Beneficiary.** Constant shared address in production (recommended) or per-node addresses
   declared in the manifest?
4. **Portal threshold.** Set `threshold = 1` as part of `tempo-zone dev` provisioning and the
   `just deploy-zone` recipe, or leave it to operators?

---

## 13. Future work (beyond the PoC)

- **Certificate as settlement authorization.** Switch to `bls12381_multisig` and have
  `ZonePortal.submitBatch` verify the Simplex finalization certificate for `nextBlockHash` (a
  Tempo hardfork replacing the EIP-712 `SettlementAttestation`). This removes the individual
  secp256k1 keys from the settlement path and makes "the fleet finalized this" the on-chain
  statement.
- **On-chain participant set and epochs.** Derive participants from `SequencerSetUpdated` at
  batch boundaries with an epoch per `sequencerSetVersion`; map ed25519 identities on-chain
  (e.g. alongside `rpcUrl`).
- **Consensus context in the header.** Extend the SPF `ZoneBlock` so headers can carry
  `TempoConsensusContext`; then adopt `Deferred` verification to hide execution latency.
- **Port the L1 executor actor** by generalizing it over the payload attributes type, and reuse
  its test harness.
- **Snapshot sync and follow mode** for `rpc_only` nodes, as in `crates/consensus/src/follow`.
- **Remove `leader*` from `ZonePortal`** and the `ActiveLeaderRemoved` guard at a hardfork.
- **Generic three-node CFT scheme** if operators standardize on three machines.

---

## Appendix A. Verified type wiring (standalone spike)

A standalone crate at `/tmp/zone-simplex-spike` (not part of the workspace) type-checks the exact
generic composition this document relies on against commonware 2026.9.0 using a mock block:
`ed25519::Scheme::signer/verifier`, `ConstantProvider<Scheme, Epoch>`, `FixedEpocher`,
`marshal::core::Actor::init` with `immutable::Archive` certificates and `prunable::Archive`
blocks, `marshal::standard::Inline::new`, `buffered::Engine`, `marshal::resolver::p2p::init`, and
`simplex::Engine::new` with `RoundRobin`. See the "Spike result" note at the end of this appendix
for the outcome and any signature corrections.

Signatures confirmed from the crate sources:

```rust
// commonware-consensus 2026.9.0
pub trait Application<E: Rng + Spawner + Metrics + Clock>: Clone + Send + 'static {
    type SigningScheme: Scheme; type Context: Epochable; type Block: Block; type Input: Send;
    fn propose(&mut self, context: (E, Self::Context), ancestry: impl Ancestry<Self::Block>, input: Self::Input) -> impl Future<Output = Option<Self::Block>> + Send;
    fn verify(&mut self, context: (E, Self::Context), ancestry: impl Ancestry<Self::Block>) -> impl Future<Output = bool> + Send;
}
pub struct Context<D: Digest, P: PublicKey> { pub round: Round, pub leader: P, pub parent: (View, D) }
impl<S: Scheme, H: Hasher> elector::Config<S> for RoundRobin<H> { type Elector = RoundRobinElector<S>; }
pub enum Floor<S: Scheme, D: Digest> { Genesis(D), Finalized(Finalization<S, D>) }
pub enum Start<S: Scheme, C: Digest, B> { Genesis(B), Floor(Finalization<S, C>) }
impl Actor { pub async fn init(context: E, finalizations_by_height: FC, finalized_blocks: FB, config: Config<..>) -> (Self, Mailbox<P::Scheme, V>, Floor);
             pub fn start(self, application: impl Reporter<Activity = Update<V::ApplicationBlock, A>>, buffer: Buf, resolver: (handler::Receiver<V::Commitment>, R)) -> Handle<()>; }
// commonware-cryptography 2026.9.0 (ed25519 certificate macro)
impl Scheme { pub fn signer(namespace: &[u8], participants: ordered::Set<PublicKey>, private_key: PrivateKey) -> Option<Self>;
              pub fn verifier(namespace: &[u8], participants: ordered::Set<PublicKey>) -> Self; }
// commonware-utils 2026.9.0
impl Faults for N3f1 { fn max_faults(n) -> u32 { (n - 1) / 3 } }   // quorum = n - f
```

Spike result: **passes `cargo check --offline`** (zero errors). The spike is checked into this
worktree at `zones/contrib/simplex-spike/` (standalone crate, not a workspace member). Corrections
and details learned while making it compile, which the PoC should follow:

- `Inline<E, S, A, B, ES>` implements `Reporter` only when the wrapped application also implements
  `Reporter<Activity = Update<B>>` (`inline.rs:694-706`). `ZoneApplication` must therefore
  implement both `Application<E>` and `Reporter`, as L1's `Inner` does; the executor mailbox is a
  second reporter combined with `Reporters::from((inline, executor))`.
- `Ancestry<B>` is a `Stream`; `ancestry.next().await` needs `futures::StreamExt` in scope.
- `commonware_runtime::Supervisor` provides `context.child(..)`; `CacheRef::from_pooler(&context,
  page_size, capacity)` builds the page cache (not `CacheRef::new`).
- `Reporter::report` returns `commonware_actor::Feedback::{Ok, Backoff, Closed}`;
  `Update::Block(block, ack)` is acknowledged through `commonware_utils::Acknowledgement::acknowledge`.
- `Scheme::signer(namespace, participants, private_key)` returns `Option<Scheme>` (`None` when the
  key is not a participant); `Scheme::verifier(namespace, participants)` is the `rpc_only` path.
  The certificate codec config for the finalization archive is
  `<Scheme as certificate::Verifier>::certificate_codec_config_unbounded()`.
- `buffered::Engine::<E, PublicKey, Block, Provider>::new(ctx, buffered::Config { public_key,
  mailbox_size, deque_size, priority, codec_config: (), peer_provider })` and
  `engine.start((sender, receiver))`.
- `marshal::resolver::p2p::init(ctx, Config { .. }, (sender, receiver)) -> (handler::Receiver<Digest>,
  Mailbox<Digest, PublicKey>)`; the tuple is passed to `marshal_actor.start(reporters,
  broadcast_mailbox, (handler_rx, resolver_mailbox))`.
- `simplex::Engine::new(ctx, Config { .. })` then `.start(votes, certificates, resolver)` where each
  is an `(impl Sender, impl Receiver)` pair with `PublicKey = ed25519::PublicKey`.
- A static `commonware_p2p::Provider` is ~15 lines: return `TrackedPeers::primary(participants)` for
  peer-set id 0 and a `tokio::sync::mpsc::UnboundedReceiver` whose sender is dropped.
- commonware 2026.9.0 uses `rand_core = "0.10"` (`Rng` bound on the application context).
- `FixedEpocher::new(NZU64!(1 << 40))` and `Epoch::new(0)` type-check with `ConstantProvider<Scheme, Epoch>`.

## Appendix B. File inventory

Delete:
`crates/zones/node/src/{role.rs, follower.rs, replication.rs, settlement_attestation.rs}`,
`crates/zones/p2p/src/{backfill.rs, capabilities.rs, protocol.rs}`,
`crates/zones/sequencer/src/settlement_manager.rs`,
manifest leadership/forced-recovery types in `crates/zones/p2p/src/manifest.rs`,
`LeadershipSink`/`LeaderTransition` consumers in `crates/zones/l1/src/subscriber.rs`.

Modify:
`crates/zones/node/src/{node.rs, engine.rs, cli.rs, rpc.rs, tx_forwarding.rs, shadow_prover.rs}`,
`crates/zones/p2p/src/{lib.rs, network.rs, runtime.rs, routing.rs, manifest.rs}`,
`crates/zones/l1/src/{queue.rs, event.rs, lib.rs}`,
`crates/zones/payload/src/builder.rs` (export `tempo_import_decision` helpers or move them),
`crates/zones/sequencer/src/{lib.rs, monitor.rs, settlement.rs, withdrawals.rs}`,
`crates/zones/node/tests/it/{utils.rs, utils/network.rs, handoff_e2e.rs, network_chaos_p2p_e2e.rs, l1_e2e.rs}`,
`zones/specs/spec.md`, `zones/invariants.md`, `zones/docs/ZONES.md`, `zones/Justfile`,
`Cargo.toml` (workspace member).

Add:
`crates/zones/consensus/**` (§6.1).

Unchanged on purpose: all Solidity under `crates/zones/contracts`, the SPF (`crates/zones/spf`),
the zone EVM and precompiles, the payload builder's block structure, the L1 subscriber's
finalized-header pipeline, the proof collector and provers.

## Appendix C. Glossary

- **View / round**: one Simplex leader slot; `Round = (Epoch, View)`.
- **Notarize / finalize / nullify**: Simplex votes; `2f+1` of each forms a certificate.
- **Marshal**: commonware actor that orders finalized blocks, stores them, and backfills gaps.
- **Inline**: marshal wrapper that runs application verification before the notarize vote.
- **Anchor**: the finalized Tempo header a zone block imports (`advanceTempo`) or the last header
  of a checkpoint range (`advanceTempoHeaders`).
- **Cursor**: a zone block's post-state view of portal progress (Tempo checkpoint, processed
  deposit number, processed token count).
- **Settlement duty owner**: the sequencer expected to call `submitBatch` for a batch.

---

## Review

Reviewed on 2026-10-20 against the zone implementation, `ZonePortal.sol`, the L1 consensus
integration, and Commonware 2026.9.0 sources. The standalone spike was independently checked with
`cargo check --offline --manifest-path zones/contrib/simplex-spike/Cargo.toml`; it passes.
That confirms the library types compose, not the runtime correctness of the zone integration.
The original proposal above is preserved; the corrections and recommendations below are not
yet incorporated into its component specifications or work estimates.

### Overall assessment

Adopting Simplex is a sound direction. It should substantially simplify leadership and failover
by replacing explicit handoffs, role-generation teardown/rebuild, leadership-dependent routing,
and routine forced recovery with one persistent consensus stack. Replacing bespoke block
replication and backfill with Commonware also reduces code the zone team must maintain.

The strongest design choices are ed25519 with round-robin election for a small static fleet,
`Inline` verification, full block replication, and consuming L1 inputs only after finalization.
However, the proposal needs revision before implementation: it conflates proof validity with
consensus authorization when lowering settlement to one signature, leaves migration and
membership transitions underspecified, and understates the risk of writing a second executor.
Some apparent simplicity comes from weaker assumptions or deferred work rather than reuse.

Recommended starting point: four voting nodes, ed25519, round-robin, `Inline`, immutable
membership for the prototype, and quorum-authorized settlement. Investigate sharing the L1
executor and storage/block utilities before committing to copies and a reduced executor.

### 1. Settlement authorization is the principal safety issue

The statement in §9 that threshold-one settlement is restricted to “the chain the fleet
finalized” is incorrect. The portal verifies a valid state transition extending its settled
anchor; it does not verify a Simplex finalization certificate.

For example:

1. The last settled portal block is `P`.
2. Simplex finalizes a valid extension `P → A`.
3. A compromised sequencer builds and obtains a valid proof for another extension `P → B`.
4. With `sequencerThreshold = 1`, that sequencer can submit `B` first.

Both extensions can execute correctly while differing in transaction ordering or inclusion.
`prevBlockHash == P` proves continuity, not agreement with the fleet. The portal can therefore
advance to a chain inconsistent with the honest nodes' finalized history. Those nodes cannot
simply reorg finalized Simplex blocks to follow it. An off-consensus submission also bypasses
the fleet's replication guarantee: a valid proof does not establish that peers retain its blocks.

Evidence: `crates/zones/contracts/src/runtime/tempo/ZonePortal.sol`, `submitBatch` and
`_verifySettlement`. These check membership, EIP-712 signatures, continuity, and proof validity,
but no Simplex certificate. A single compromised sequencer is a weaker compromise threshold
than a leader plus a second signer; the exposure is not equivalent to the existing 2-of-3 path.

Recommendation: retain quorum EIP-712 settlement attestations initially, with signers accepting
only statements for locally Simplex-finalized batches. For four voting nodes, use three
settlement signatures. Later, replace the separate attestation protocol with contract
verification of consensus authorization. The certificate-based path in §13 needs a complete
design for binding the batch statement and participant configuration, not just a scheme swap.

If threshold one is an intentional trusted-operator PoC requirement, explicitly document this
weaker trust model. Do not claim end-to-end tolerance of one compromised sequencer. Retaining
quorum attestations also changes the proposed deletions, P2P channels, and work breakdown.

### 2. Fleet size, DKG, and reuse of L1 components

With the proposed default `N3f1` scheme:

| Voting nodes | Required votes | Unavailable nodes tolerated |
|---|---:|---:|
| 3 | 3 | 0 |
| 4 | 3 | 1 |

RPC-only nodes do not count toward the quorum. Use four voting nodes to tolerate one unavailable
node. More generally, Commonware calculates `f = floor((n - 1) / 3)` and quorum `n - f`;
the document's `2f+1` shorthand applies when `n = 3f+1`, not every supported fleet size.

The proposed ed25519 scheme needs no DKG ceremony, threshold shares, or VRF election. Operators
still provision individual keys and agree on the manifest. This is a reasonable simplification
relative to L1. The custom three-node crash-only option changes protocol assumptions and needs
its own safety/liveness analysis and tests; describing it as a “one-file follow-up” understates
the assurance work, regardless of implementation size.

The design reuses L1's upstream consensus libraries, not the entire `tempo-consensus`
implementation. `zone-consensus`, its application/executor, settlement duty, and cursor-aware L1
input handling are new zone integration code. Copies of digest, block, metrics, and storage code
create maintenance duplication. Prefer shared components where their actual dependencies allow
it, without forcing L1-specific epochs, DKG, or payload semantics into zones.

### 3. Full replication and the actual durability barrier

Every healthy node is intended to receive and execute every finalized block, including catching
up after an outage. This is full replication, not sharding. Finalization does not wait for all
nodes: three of four can progress while the fourth is offline. A notarization does not imply
that every honest participant has already executed the block; some may still be behind.

Correct §4's statement that `certify` is the default `true`. The chosen `Inline` wrapper
overrides certification and waits for durable block storage before allowing a finalize vote.
The leader's own proposal follows this durability path too. Marshal also gates finalized
delivery on archive durability. See the
[Commonware 2026.9.0 Inline source](https://docs.rs/commonware-consensus/2026.9.0/src/commonware_consensus/marshal/standard/inline.rs.html)
and `marshal/core/actor.rs`.

For four nodes and a three-vote finalization certificate, at least two honest participants have
durably stored the block under the one-Byzantine-fault assumption. In a crash-only execution,
all three voters have stored it. Settlement can rely on finalization rather than separately
collecting acknowledgements from every peer's reth database or proof WAL. Durable blocks allow
surviving peers to replay execution and regenerate witnesses.

This guarantee requires settlement to use only the finalized chain and assumes the configured
fault budget and surviving durable copies. It does not cover arbitrary simultaneous disk loss,
nor the off-consensus settlement attack described above.

### 4. Explicitly gate settlement on Simplex finality

The existing monitor's `BatchPreparer::process_available_blocks` scans through
`provider.last_block_number()` (`crates/zones/sequencer/src/monitor.rs`). The current design
largely equates canonical production with immediate finality. The proposal introduces
speculative execution and fork-choice changes while building on notarized parents.

Specify an explicit Simplex-finalized height/hash boundary for batch preparation and submission,
rather than relying implicitly on persisted-chain behavior. Preserve the same constraint when
restarting, reconciling portal state, and failing over settlement duty.

Required test: a batch-boundary block is built and becomes locally visible, but its proposal
never finalizes; no node submits that batch.

### 5. Cursor-relative imports must preserve deferred portal work

Selecting imports relative to the proposed parent's post-state is correct. However, §6.4 must
specify how selection and verification retain access to deposits and token enablements crossed
by finalized checkpoint-only blocks.

Today, `PendingDeposits::defer_through` removes those entries from the pending queue and retains
their unprocessed events in `DeferredPortalWork`; `operational_work` includes that work in the
next full import (`crates/zones/l1/src/queue.rs`). Iterating only retained pending entries after
a checkpoint finalizes would omit these events. Deferred work cannot become merely restart
bookkeeping unless another retained representation fully replaces it.

Both proposal selection and verification need a consistent parent-relative view of pending and
deferred events. Test multiple checkpoint-only blocks followed by a full import, speculative
descendants, finalization while a proposal is being constructed, and restart before the full
import. Assert that each deposit/token event is included exactly when owed, without omission
or duplication.

### 6. The reduced executor needs a stronger justification and contract

One engine call in flight is useful, but does not by itself make scheduling correct. Proposal
cancellation, ancestry fetches, finalization, and stale build results can overlap. Removing L1's
build arbitration and pending-head convergence transfers responsibility for those interactions
to new zone code.

First investigate generalizing the existing L1 executor over payload attributes and adding
zone-specific finalization hooks. If a reduced executor remains preferable, specify and test:

- Cancellation and stale-result rejection across view changes.
- Finalization priority and prevention of fork-choice updates conflicting with finalized state.
- Bounded ancestry fetching and progress when execution is behind marshal.
- Recovery when marshal, reth, and the witness WAL have persisted different amounts of progress.
- Queue reconciliation and acknowledgement ordering during retries and restart.

Treat this as a correctness-sensitive implementation, not merely a smaller adapter. The
type-check spike provides no evidence for these runtime behaviors.

### 7. Existing-zone migration is not yet designed

The §6.6 startup rule requires the execution layer to be at genesis if the certificate archive
is empty. An existing zone has a non-genesis chain and no Simplex certificates, so the specified
startup path cannot migrate it directly.

Label the initial prototype fresh-zone-only, or add an explicit cutover procedure defining an
agreed height/hash, reconciliation with the portal's settled anchor, fencing of old producers,
initialization of the new consensus trust anchor, and interrupted-migration restart behavior.
Changing the manifest alone is insufficient. Do not silently discard or reinterpret existing
finality or unsettled history during cutover.

### 8. Membership changes need a configuration-transition design

§5.4's coordinated restart at a known height is not a complete membership protocol. Historical
certificates and persisted voting state belong to the old configuration. Replacing keys while
retaining epoch zero and the old journals is not automatically a safe or verifiable transition.

For the PoC, make membership immutable. For production, define an agreed transition checkpoint,
old/new certificate verification rules, voting-state handling, and fencing of the old
configuration. Include operational replacement of a permanently lost machine and rotation of
a compromised key. A portal sequencer-set update is not by itself a Simplex membership change.

### 9. Portal leadership and forced recovery

No Solidity change is strictly needed to demonstrate rotating block leadership: `submitBatch`
permits any active sequencer and never checks the stored `leader`. Threshold one is also already
supported, subject to the safety caveat above. Nevertheless, `leader`, `leaderEpoch`,
`leaderActivationTempoBlock`, and `LeaderUpdated` become obsolete as consensus controls and
should eventually be removed or explicitly deprecated through the appropriate contract upgrade.

Until then, `_replaceSequencerSet` still rejects removing the stored leader with
`ActiveLeaderRemoved`; operators must move that stored leadership to a remaining member first.
Document that compatibility behavior so portal state is not mistaken for the current Simplex
proposer. Also correct §2.1's implication that a crashed leader's cooperation is required for
`setLeader`: the function is callable by a sequencer or admin.

The manifest forced-recovery override can be removed for ordinary leader failure while a quorum
survives. Simplex handles that through view changes. A separate disaster-recovery procedure is
still necessary for quorum loss, storage loss, membership replacement, and migration. Consensus
cannot recreate missing data or form a quorum without enough participants.

### 10. Qualify recovery and timing claims

“Resync from any surviving peer” requires that peer to retain all required history. The hybrid
store falls back to reth after its cache window, and reth may prune history; see
`crates/consensus/src/storage/hybrid/mod.rs`. With snapshot sync excluded, replay from genesis
requires an archival source. Specify retention requirements instead of treating the marshal
cache as permanent history.

A leader crash is not guaranteed to recover in exactly one `leader_timeout` under arbitrary
network latency, storage stalls, or delayed L1 observations. Describe the timing as a nominal
healthy-network expectation rather than an unconditional upper bound.

Likewise, notarization alone does not give unconditional forced inclusion. Commonware's
`simplex/mod.rs` conditions that property on the absence of a covering nullification
certificate. Correct the §8 failure table accordingly; reserve unconditional finalized-chain
claims for finalization under the protocol's assumptions.

### 11. P2P: what is reused, replaced, and still zone-specific

The proposal changes the protocols carried between sequencers while retaining the existing
Commonware networking foundation. It does not replace everything with Simplex itself.

| Responsibility | Proposed owner | Effect on current code |
|---|---|---|
| Connections, authentication, peer channels | `commonware_p2p::authenticated::lookup`, ed25519 identities, manifest peers | Reuse and rewire |
| Transaction propagation and txpool admission | Zone forwarding tasks over a Commonware channel | Retain, simplify routing |
| Proposed full-block broadcast | Commonware buffered broadcast | Replace custom block broadcaster |
| Missing-block fetch and finalized catch-up | Commonware marshal and resolver | Replace bespoke backfill |
| Votes, certificates, leader rotation | Commonware Simplex | Library protocol with zone wiring |
| Zone block construction and validation | Zone application/executor and reth | Zone-specific integration remains |
| Portal settlement attestations | Separate EIP-712 protocol | Removed only under threshold one; retain under the recommendation above |

Recommended transaction path:

```text
Client → transaction-accepting RPC node → all voting sequencers' pools
                                                ↓
                                   current leader builds a block
                                                ↓
                                   buffered full-block broadcast
                                                ↓
                                   execution and zone validation
                                                ↓
                                   Simplex votes and finalization
```

Forward to all voting sequencers rather than tracking the current leader, so the next leader
already has pending transactions. The existing `crates/zones/node/src/tx_forwarding.rs` provides
local-transaction forwarding, pool-based retry/reconciliation, received-transaction admission,
and avoidance of repeated propagation of externally received transactions. Reuse that machinery
while removing leadership-dependent routing. Simplex does not supply an Ethereum transaction
mempool or transaction gossip protocol.

Clarify §6.8: every RPC-only node that accepts transaction submissions must also run outbound
forwarding to voting peers. The text explicitly wires forwarding for quorum nodes but does not
clearly specify the corresponding RPC-only task. Non-voting status does not remove this duty.

Consensus signatures are not merely collected by a central leader. Simplex distributes votes
and certificates among participants so progress can continue after a leader fails. Zone code
still supplies block construction/verification callbacks and runtime wiring, but should not
reimplement voting, certificate formation, or missing-block recovery.

Simplex votes and EIP-712 settlement attestations are distinct: the former establish consensus
on blocks; the latter authorize the batch statement the current portal accepts. Deleting the
settlement channels does not make Simplex certificates usable by the existing contract. The
P2P inventory and deletion list must follow the chosen settlement-security design.

### 12. Additional validation gates and scope implications

Extend §11 beyond type composition and short healthy-cluster tests:

- Reject settlement of a valid alternative chain lacking consensus authorization.
- Never submit a locally visible but unfinalized batch boundary.
- Exercise unclean crashes around certification, archive sync, finalization delivery, witness
  persistence, FCU, and acknowledgement; verify replay preserves the finalized chain.
- Restart the fleet with reth behind marshal and test recovery beyond the hot-cache window.
- Exercise deferred deposits/token enablements across checkpoints, speculative parents, and restart.
- Verify transaction submission through RPC-only nodes, forwarding retries, and leader changes.
- Test migration and membership transitions if either is claimed as supported; otherwise reject
  unsupported configurations explicitly.

Revisit the approximately 22 engineer-day estimate after deciding executor reuse, settlement
authorization, and fresh-zone versus migration scope. The spike establishes API compatibility;
it does not establish the schedule for runtime integration, fault testing, or production
operations. The main simplification remains compelling, but should come from retiring custom
leadership and replication machinery rather than silently weakening settlement authorization.
