# Tempo Zone P2P

This crate provides the static networking for a Simplex-sequenced Tempo Zone. A manifest defines
the participant set (names, addresses, Ed25519 identities, individual secp256k1 addresses) and the
Simplex timing parameters. Each node loads its own Commonware Ed25519 identity and individual
secp256k1 key and validates that both belong to the same manifest member.

Every participant runs the same long-lived task set: a Commonware Simplex instance over the zone
block stream (`zone-consensus`), transaction forwarding to every other participant, and settlement
with a rotating duty. Leadership rotates every view inside consensus; a crashed leader costs one
view timeout and needs no operator action. There are no roles, no portal leader, and no forced
recovery.

If a manifest is not specified, `tempo-zone` runs its single-sequencer startup path for
development.

## Commonware network

Nodes use [Commonware](https://commonware.xyz/) to communicate. Discovery is disabled: the
manifest supplies the complete peer set, including each peer's address and Ed25519 public key.

The Commonware Ed25519 identity authenticates every network message and is also the node's
Simplex vote key. The individual secp256k1 key is the node's on-chain identity: its address is
registered with `ZonePortal`, and the node signs and submits settlements with it.

The authenticated-network namespace includes the P2P wire-protocol version, Tempo L1 chain ID,
ZonePortal address, and zone ID. This keeps nodes from different local, test, or production
environments from connecting when a key or endpoint is accidentally reused. Consensus derives its
signing namespace from the network namespace.

Each node also logs a `membership_digest` covering every member's Ed25519 identity and settlement
address. It is diagnostic only: compare it across nodes to spot a manifest mismatch. Peer
addresses are excluded, so relocating a node does not change it.

The runtime registers six channels on one authenticated network: Simplex votes, certificates,
certificate backfill (resolver), proposed-block broadcast, marshal backfill of finalized blocks,
and raw transaction forwarding. Transactions are forwarded to every other participant, so every
future leader already holds them when its view starts. Every receiver decodes and validates each
forwarded transaction through its own pool again.

## Manifest example

The manifest is TOML and must contain at least four nodes: Commonware's `N3f1` fault model needs
four voters to keep finalizing while one of them is unavailable. The following shows the
configuration shape:

```toml
[consensus]
leader_timeout_ms = 2500         # all keys optional; these are the defaults
certification_timeout_ms = 4000
timeout_retry_ms = 10000
skip_timeout_ms = 12000
fetch_timeout_ms = 2000
proposal_anchor_wait_ms = 1500
settlement_failover_ms = 30000

[[nodes]]
name = "seq-0"
ed25519_public_key = "0xs0..."
secp256k1_address = "0x1111111111111111111111111111111111111111"
address = "seq-0.zone.internal:9200"
# beneficiary = "0x..."          # optional fee recipient; defaults to the shared sequencer key

[[nodes]]
name = "seq-1"
ed25519_public_key = "0xs1..."
secp256k1_address = "0x2222222222222222222222222222222222222222"
address = "seq-1.zone.internal:9200"

[[nodes]]
name = "seq-2"
ed25519_public_key = "0xs2..."
secp256k1_address = "0x3333333333333333333333333333333333333333"
address = "seq-2.zone.internal:9200"

[[nodes]]
name = "seq-3"
ed25519_public_key = "0xs3..."
secp256k1_address = "0x4444444444444444444444444444444444444444"
address = "seq-3.zone.internal:9200"
```

The `[consensus]` table is optional and so is every key in it. The loader rejects timing values
that Commonware would assert on at startup: `proposal_anchor_wait_ms < leader_timeout_ms <
certification_timeout_ms < skip_timeout_ms`, `timeout_retry_ms < skip_timeout_ms`, and non-zero
`fetch_timeout_ms` and `timeout_retry_ms`. `settlement_failover_ms` is how long a node that does
not own a batch waits before settling it in the owner's place (see `simplex_poc.md` at the
repository root for the settlement trust model).

`beneficiary` overrides the fee recipient of that node's proposals. Every participant checks it
when verifying a proposal, so all manifests must agree on it.

The manifest loader validates that:

- there are at least four nodes;
- node names, Ed25519 public keys, and secp256k1 addresses are unique;
- every address has a non-zero port;
- both local private keys correspond to the same manifest member.

Membership is static: changing it requires a fresh zone.

At startup, the node requires the configured `ZonePortal` to be deployed at the current L1 tip,
then checks the manifest against it. The node refuses to start unless every node's
`secp256k1_address` is a registered portal sequencer and `sequencerThreshold()` is one, because
each node settles with a single self-signed attestation. Registered sequencers the manifest does
not list only warn.

## Generate a Commonware identity

Generate a unique Ed25519 key for each node with `cargo zone-xtask`:

```bash
cargo zone-xtask generate-p2p-key --out seq-0-p2p.key
```

The command writes the hex-encoded private key to the requested file and prints
the corresponding public key for the manifest.

## Start a node with a manifest

Add these arguments to the node's normal command:

```text
--sequencer.manifest ./zone-manifest.toml
--p2p.key ./seq-0-p2p.key
--secp256k1.key ./seq-0-secp256k1.key
--p2p.listen 0.0.0.0:9200
```

Use each node's own key files and listener address. Every node also needs the shared
`--sequencer-key-file`: any node may propose, and the shared key is the zone's ECIES private key
for encrypted deposits. The individual secp256k1 key must be distinct per node; reusing the shared
key would collapse several nodes into one settlement identity. The paths supplied through
`--p2p.key`, `--secp256k1.key`, and `--sequencer-key-file` may point to either regular files or
FIFOs.

The `--sequencer` flag conflicts with `--sequencer.manifest` because the manifest already means
this node sequences.

DNS peer addresses do not provide a stable egress IP for Commonware's inbound source-IP filter. A
manifest containing any DNS peer therefore requires the explicit `--p2p.bypass-ip-check` flag. The
flag disables source-IP filtering for all inbound P2P connections, not only the DNS peer. Only use
it when a network-level policy restricts the P2P port to the configured peers; Ed25519 manifest
membership authentication remains enforced.

## Block catch-up

Finalized blocks and their certificates live in marshal's archive under `<datadir>/consensus`. A
node that restarts, or that lost its disk, backfills every missing finalized block from any peer
over the marshal channel and replays it into reth. No separate backfill protocol exists.
