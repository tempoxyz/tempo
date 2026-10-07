# Tempo Zone P2P

This crate provides the static networking and the leadership schedule for a
multi-sequencer Tempo Zone. A manifest defines the static peer topology (names, addresses,
Ed25519 identities, individual secp256k1 addresses). Each node loads its own Commonware
Ed25519 identity and validates that it appears in the manifest.

Which member *leads* (produces blocks) is not decided by the manifest: normally it is derived
from finalized Tempo L1 state — the `ZonePortal`'s `leader`, `leaderEpoch`, and
`leaderActivationTempoBlock` fields and its `LeaderUpdated` event. Every observed transition
is retained in an activation-indexed `LeadershipSchedule`.

For manual crashed-leader recovery, the operator stops the nodes, selects a canonical tip shared by
the survivors, adds the same `[forced_recovery]` directive to every manifest, and restarts them.
Each node verifies that the configured hash remains in its local canonical chain before any role
task starts. On the initial recovery start it should be the canonical head shared by every
survivor. On a later restart it may be an ancestor of the local head; the node reconstructs the
original recovery anchor and epoch instead of starting a new recovery window. The selected
replacement governs from the next Tempo anchor until the first subsequent finalized portal
transition reaches its activation anchor. Nodes never submit that transition automatically: the
operator may call the ordinary `zone_setLeader` RPC whenever the zone is ready to return to the
on-chain schedule.

Restarting during recovery assumes every participating node's descendants of
`recovery_block_hash` belong to the same chain produced by the selected, non-equivocating recovery
leader. Canonical ancestry is local evidence and cannot prove cross-node convergence; operators
must compare the survivors' heads before restarting if that assumption is in doubt. The configured
L1 RPC must also serve historical Portal state at the Tempo block embedded in the recovery
checkpoint. A node fails closed if the checkpoint is unknown or non-canonical, historical state is
unavailable, or skipped Portal epochs make the recovery boundary ambiguous.

After a normal Portal transition ends recovery, a restart skips the completed stale directive and
logs a removal warning. Operators should still remove the directive from every manifest promptly.

If a manifest is not specified, `tempo-zone` retains its existing single-sequencer startup
behavior.

## Roles

- The **leader** runs the existing block-production and L1-settlement tasks in
  addition to the P2P network.
- A **follower** joins the P2P network and receives blocks from the leader, validating and importing the blocks and sending a signed block hash back to the leader
- An **rpc-follower** replicates and validates exactly like a follower, but never signs a
  settlement attestation and is not registered with `ZonePortal`. It is a hot standby for public
  RPC: it serves reads from its own imported chain and forwards transactions to the leader, so
  neither the leader nor a quorum follower has to be exposed to the internet. Mark one with
  `rpc_only = true` on its manifest node.

Because rpc-followers are outside the on-chain quorum, they neither raise nor lower the signature
threshold. Quorum membership is the one thing a leadership transition never changes: the portal can
only name a registered sequencer, and an rpc-follower is not one. Promoting a standby is a manual
operation — provision an individual secp256k1 key, register it with `ZonePortal`, drop `rpc_only`
from the manifest, and restart.

Roles are dynamic: a node promotes or demotes at finalized leadership activation
boundaries, driven by the node's role controller. The manifest's
`leader_ed25519_public_key` is only a legacy bootstrap used until the portal reports a
nonzero leader; the (optional) `--sequencer.role` CLI argument is only an assertion checked
against that bootstrap — `leader`, `follower`, or `rpc-follower`. There is no automatic election:
leadership changes only through an operator-triggered `setLeader` transaction finalized on L1.
 

## Witness support

Live blocks and backfill responses use bare RLP unless the receiving peer has explicitly
advertised support for witness envelope v1. Witness collection and proving remain independent
of this transport choice; followers can collect witnesses locally when they receive bare RLP.

Every node announces `ResponseFrame::Capabilities(1)` every 5 seconds using response frame
`[2, 1]` on the existing backfill-response channel. The payload is a capability version byte;
version 1 means witness-envelope v1 is supported. Version 0 and unknown versions do not enable
witnesses, even if the peer previously announced version 1. This is an unsolicited control frame,
independent of backfill request IDs and leadership. Older nodes ignore the unknown response tag;
a new Commonware channel would instead disconnect them. Block/completion frames and the
authenticated network namespace are unchanged. Only authenticated remote manifest members can
update capability state.

Advertisements expire after 15 seconds without a refresh. The state is shared by live replication
and backfill and starts empty after a local restart. Commonware does not expose connection
generations, so a remote rollback may receive witness envelopes until the last advertisement
expires; it then automatically receives bare RLP again. This is a bounded fallback, not an
instantaneous rollback guarantee.

## Commonware network

Nodes use [Commonware](https://commonware.xyz/) to communicate. Discovery is disabled: the
manifest supplies the complete peer set, including each peer's address and
Ed25519 public key.

The Commonware Ed25519 identity answers which configured network peer sent a
message. It is not an on-chain quorum identity. The quorum design will
also give each node an individual secp256k1 key whose address is
registered with `ZonePortal`. 

The authenticated-network namespace includes the P2P wire-protocol version,
Tempo L1 chain ID, ZonePortal address, and zone ID. This keeps nodes from different local, test,
or production environments from connecting when a key or endpoint is accidentally reused.

Each node also logs a `membership_digest` covering every member's Ed25519 identity, `rpc_only`
standing, and settlement address. It is diagnostic only — compare it across nodes to spot a
manifest mismatch, whose symptom is settlement stalling because the leader collects signatures
from a different set than it needs. Peer addresses are excluded, so relocating a node does not
change it.

## Manifest example

The manifest is TOML and must contain at least three quorum nodes. The following shows
the configuration shape:

```toml
leader_ed25519_public_key = "0xleader..."

[[nodes]]
name = "leader"
ed25519_public_key = "0xleader..."
secp256k1_address = "0x1111111111111111111111111111111111111111"
address = "leader.zone.internal:9200"

[[nodes]]
name = "follower-a"
ed25519_public_key = "0xfa..."
secp256k1_address = "0x2222222222222222222222222222222222222222"
address = "follower-a.zone.internal:9200"

[[nodes]]
name = "follower-b"
ed25519_public_key = "0xfb..."
secp256k1_address = "0x3333333333333333333333333333333333333333"
address = "follower-b.zone.internal:9200"

[[nodes]]
name = "operator-rpc"
ed25519_public_key = "0xrpc..."
address = "operator-rpc.zone.internal:9200"
rpc_only = true

[[historical_leaders]]
ed25519_public_key = "0xretired-leader..."
secp256k1_address = "0x4444444444444444444444444444444444444444"
```

`rpc_only` defaults to `false`, so existing manifests keep their current meaning.

`historical_leaders` maps a retired Portal sequencer address to the Ed25519 identity that authored
blocks while that address was leader. Keep an entry while any persisted node checkpoint can still
precede the leader's removal, or while finalized leadership events that name it may need replay.
These entries are identity history only: they are excluded from the P2P topology and settlement
quorum, cannot be selected by `zone_setLeader` or `[forced_recovery]`, and are not checked against
the Portal's current registered sequencer set. Once every retained checkpoint and replay window is
past that leader's last epoch, the entry can be removed.

To recover a crashed leader, add this top-level table before restarting the fleet:

```toml
[forced_recovery]
leader = "follower-a"
recovery_block_hash = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

`leader` is a manifest node name and must identify a quorum member. The hash must be the shared
canonical head on the first recovery start. On subsequent restarts it may be a canonical ancestor;
the first recovery anchor and Portal epoch are recovered from the zone state and historical Portal
state at that checkpoint, so no independently configured height or epoch can disagree with the
hash.

An `rpc_only` entry declares no `secp256k1_address` and the node is started without
`--secp256k1.key`. It never signs a settlement attestation, so the key would be dead weight —
and registering such an address with `ZonePortal` would add a signer the zone never collects a
signature from, stalling settlement on a threshold it can no longer reach.

The manifest loader validates that:

- there are at least three quorum nodes (nodes without `rpc_only`);
- the leader is not `rpc_only`;
- `secp256k1_address` is present on every quorum node and absent on every `rpc_only` node;
- node names, Ed25519 public keys, and secp256k1 addresses are unique;
- historical leader addresses do not duplicate another historical or active node address, and
  their Ed25519 identities do not alias an `rpc_only` node;
- every address has a non-zero port;
- `leader_ed25519_public_key` identifies one of the nodes;
- both local private keys correspond to the same manifest member.

At P2P startup, the node requires the configured `ZonePortal` to be deployed at the current L1 tip,
then checks the manifest against it. The persisted Zone genesis anchor may still precede portal
deployment so the creation block can be replayed. The node refuses to start unless every quorum
node's `secp256k1_address` is a registered portal sequencer and `sequencerThreshold()` is nonzero
and reachable by the manifest quorum. These failures would otherwise surface as stalled settlement
at the next batch boundary.

Registered sequencers the manifest does not list only warn — a demoted standby whose key was never
deregistered holds a share of the threshold nobody signs for, but failing on it would make every
membership change a window in which no node can start.

Apply a `ZonePortal` registration before the manifest edit that adds the node, and the manifest edit
before deregistering.

## Generate a Commonware identity

Generate a unique Ed25519 key for each node with `xtask`:

```bash
cargo run -p tempo-xtask -- generate-p2p-key --out leader-p2p.key
```

The command writes the hex-encoded private key to the requested file and prints
the corresponding public key for the manifest. 

## Start a node with a manifest

Add these arguments to the node's normal command:

```text
--sequencer.manifest ./zone-manifest.toml
--p2p.key ./leader-p2p.key
--secp256k1.key ./leader-secp256k1.key
--p2p.listen 0.0.0.0:9200
--sequencer.role leader
```

Use each node's own key files and listener address. Quorum followers use their individual
secp256k1 keys to sign settlement attestations after importing and validating blocks.
The paths supplied through `--p2p.key`, `--secp256k1.key`, and `--sequencer-key-file` may point
to either regular files or FIFOs.

An rpc-follower is started with **neither** key: it omits `--secp256k1.key` (it never signs an
attestation) and `--sequencer-key-file` (it never produces a block). The shared
sequencer key is also the zone's ECIES private key for encrypted deposits, so provisioning it on
the internet-facing standby would put deposit recipients and memos within reach of a host
compromise. Startup rejects that key-file flag on an `rpc_only` node rather than ignoring it.
This key is independent from the shared `--sequencer-key-file`; reusing that shared key
would collapse several nodes into one recoverable quorum identity.

Add `--sequencer.enable-prover` to run the detached shadow prover on this follower, and optionally
`--sequencer.prover-address HARDFORK=HOST:PORT` (repeat per L1 hardfork) to use remote provers. The follower scans finalized
`submitBatch` transactions, decodes the accepted quorum certificate inputs, and proves the exact
anchor committed by the transaction after the matching Zone range is canonical locally. This is
observational: proof success or failure never changes settlement or the follower's RPC service.

The `--sequencer` flag conflicts with `--sequencer.manifest` because the
manifest determines whether the node starts the sequencer tasks.

DNS peer addresses do not provide a stable egress IP for Commonware's inbound
source-IP filter. A manifest containing any DNS peer therefore requires the
explicit `--p2p.bypass-ip-check` flag. The flag disables source-IP filtering for
all inbound P2P connections, not only the DNS peer. Only use it when a network-level
policy restricts the P2P port to the configured peers; Ed25519 manifest membership
authentication remains enforced.

## Block catch-up

Every node probes for missing blocks when P2P starts and retries while its eligible peers are
offline or a gap remains. Every role can serve bounded 64-block response pages from its persisted
canonical chain.

Catch-up sources are always quorum members — never a standby, so no node takes chain data from an
internet-facing one. Within the quorum, a node asks only the leader while it answers, and widens to
the other quorum members once the leader misses the response timeout. That fallback is what lets an
rpc-follower catch up through a leader outage.

Preferring the leader is a trust boundary, not load balancing. A live block is checked against the
scheduled leader of the anchor it embeds, but a backfilled block has no sender to check — only
parent linkage, L1 anchor, execution and hash. Those pass for a valid *alternative* chain too, so a
compromised quorum member could serve pages that build a fork the quorum will never settle. Asking
the leader first limits that to a leader outage, counted by
`zone_p2p_backfill_requests_without_leader_total`.

Removing it altogether needs the block to carry a leader signature over its own hash, which is a
wire-format change tracked separately.

Backfilled blocks use the same RLP representation and import path as live replicated blocks. A
node buffers out-of-order arrivals, then re-executes and canonicalizes only the next block after
its local head. Parent linkage, execution results, block hash, and forkchoice validation therefore
remain mandatory during catch-up; authenticated transport alone never makes a returned block
canonical.

## Transaction forwarding

Commonware carries blocks, catch-up traffic, and transactions on independent authenticated
channels. A node that is not the leader of the next Tempo anchor it will consume sends canonical
EIP-2718 transaction bytes to every other quorum member. During a scheduled handoff, this lets
both the outgoing and incoming leaders retain transactions before the activation boundary. An
rpc-follower may originate forwarding, but it does not receive forwarded transactions because it
is outside the on-chain quorum.

This permits operator RPC to be exposed on followers while keeping the leader's RPC private. Every
quorum receiver decodes and validates each forwarded transaction through its pool again; follower
validation is not trusted. Only the active leader selects and orders transactions into blocks.
Followers periodically retry live pool transactions, recovering from listener overflow and
temporary leader disconnections.
