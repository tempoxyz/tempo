# 08 — P2P and sync

This chapter specifies how Tempo nodes talk to each other and how a node obtains, authenticates, persists and serves finalized history. It covers:

- the validator consensus network (commonware authenticated `lookup` transport), its peer sets and its six channels;
- the execution-layer devp2p network, including the Tempo `tempo/1` RLPx subprotocol that gossips finalization certificates;
- block and certificate backfill, retention, syncing from genesis and consensus snapshots;
- follower mode (certificate and block sources, verification, identity installation, execution-layer forkchoice driving);
- persistence and crash-safety requirements;
- key and share file formats (informative).

The consensus protocol itself (Simplex, the threshold scheme, certificate formats and verification, epochs, the DKG and the on-chain DKG artifacts, the network-identity trust root) is specified in 07-consensus.md. This chapter references those definitions by name and does not restate them.

Nothing in this chapter is fork-gated within T0..T13: every rule below applies to every mainnet block height. (Fork-gated consensus behaviour such as the T12 leader elector lives in 07-consensus.md.) Where a rule depends on the fork schedule it is stated explicitly using the fork predicate of 01-chain-and-forks.md.

## 0. Conventions and pinned dependencies

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in RFC 2119.

Wire formats that this chapter references rather than restates are pinned as follows:

| Dependency | Pin | Used for |
|---|---|---|
| commonware | crates.io `2026.9.0` (`commonware-p2p`, `commonware-stream`, `commonware-consensus`, `commonware-resolver`, `commonware-broadcast`, `commonware-cryptography`, `commonware-codec`, `commonware-storage`, `commonware-utils`; git tag `v2026.9.0`, commit `d476a2361ce6840d2b9d0aa6fb30a924429046d4`) | consensus p2p transport, handshake, codecs, Simplex messages, resolver and marshal wire, archives |
| reth | git rev `966010c905449163ef161530a5ee95ac1e0c8487` | devp2p (discv4, RLPx, `eth` wire), engine API semantics |
| Ethereum | execution-specs Osaka, devp2p specs (RLPx, `eth`), EIP-2124 | devp2p |

Codec notation (commonware codec, 02-encoding.md): `varint(x)` is the commonware `UInt` LEB128 encoding of an unsigned integer; `u8`, `u64be` are fixed-width big-endian integers; `bytes(x)` is `varint(len(x)) || x`; a tuple `(A, B)` encodes as `enc(A) || enc(B)`; an `Option<T>` encodes as a `bool` byte (`0x00`/`0x01`) followed by `T` when present.

Terms:

- **CL** / **EL**: the consensus layer and the execution layer of a node. In the reference implementation both run in one process; the EL is reth.
- **Validator**: a node running the consensus engine with an ed25519 signing key (`--consensus.signing-key`). It may or may not hold a BLS share in a given epoch (signer vs verifier, 07-consensus.md).
- **Follower**: a node that does not vote. It obtains finalization certificates and blocks from other nodes, verifies them and drives its EL (`tempo node --follow`).
- **Marshal**: the commonware `commonware_consensus::marshal::core::Actor` instance that orders finalized blocks, persists finalizations and blocks, and repairs gaps.
- **Finalization**: `commonware_consensus::simplex::types::Finalization<Scheme<ed25519::PublicKey, MinSig>, Digest>` with `Scheme = commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme` and `Digest` = the 32-byte block hash (07-consensus.md §7 "Certificates and follower verification").
- **Block (consensus encoding)**: the RLP encoding of the Tempo execution block (header + body) as specified in 02-encoding.md, with no additional framing. Decoding MUST reject a block whose body does not match the header commitments (transactions root, ommers hash, withdrawals root) and a block whose header carries a block-access-list hash.
- **epoch(h)**, **last(E)**, **first(E)**: the fixed epoch mapping of 07-consensus.md with `epochLength = 21600` on mainnet (chain id 4217) and Moderato (chain id 42431). The boundary block of epoch `E` is `last(E)`; its `extra_data` is the `OnchainDkgOutcome` for epoch `E+1`. The genesis block (height 0) plays the role of the boundary of "epoch −1": its `extra_data` is the outcome for epoch 0.
- **boundary_for(E)**: `0` if `E = 0`, else `last(E−1)`. The outcome in `header(boundary_for(E)).extra_data` describes epoch `E`.

Reference implementation: crates/consensus/src (consensus and follow engines), crates/node/src/gossip (tempo/1 transport), bin/tempo/src (snapshot commands).

## 1. Overview

A Tempo node has two independent network stacks:

| Stack | Who | Identity | Transport | Purpose |
|---|---|---|---|---|
| Consensus p2p | validators only | ed25519 consensus key (the `publicKey` registered in ValidatorConfigV2) | commonware `p2p::authenticated::lookup` over TCP, encrypted with `commonware_stream::encrypted` | votes, certificates, block broadcast, backfill, DKG |
| Execution devp2p | every node | secp256k1 node key (enode) | discv4 + RLPx | transaction gossip, header/body serving, EL sync, `tempo/1` certificate gossip |

Validators never accept consensus data from devp2p: they publish certificates on `tempo/1` but discard inbound `tempo/1` frames. Followers have no consensus p2p connection; they obtain certificates from an upstream node over JSON-RPC and, optionally, from `tempo/1` peers.

```mermaid
flowchart TB
  V1["Validator A"] <-->|"lookup p2p: channels 0-5"| V2["Validator B"]
  V1 -->|"tempo/1 NewFinalization (publish only)"| F["Follower"]
  F -->|"consensus_subscribe / getFinalization (WebSocket JSON-RPC)"| R["Upstream RPC node"]
  F <-->|"devp2p eth: headers, bodies, txs"| V1
  F <-->|"tempo/1 (ingest and relay)"| F2["Other follower"]
```

## 2. Validator consensus network

### 2.1 Identity

A validator's consensus identity is its ed25519 key pair (commonware `commonware_cryptography::ed25519::{PrivateKey, PublicKey}`; 32-byte public key). The public key MUST equal the `publicKey` (bytes32) of the validator's ValidatorConfigV2 entry (precompiles/validator-config-and-zones.md). The same key authenticates the p2p handshake, is the participant identifier in Simplex and the DKG (players and dealers are ordered sets of these keys), and signs DKG dealer logs (07-consensus.md). Simplex votes and certificates are *not* signed with ed25519; they carry BLS12-381 threshold partials or recovered signatures (07-consensus.md).

> **Open conflict C-P2P-01**: TIP-1017 says the ed25519 key is used for signing all consensus p2p messages; the code uses it only for transport authentication and DKG artifacts, while votes and certificates carry BLS threshold signatures. See [conflicts](conflicts.md#c-p2p-01).

### 2.2 Transport and handshake

Validators MUST implement the commonware 2026.9.0 `commonware_p2p::authenticated::lookup` network with the following parameters. "Normative" parameters MUST be used for interoperability or because peers depend on them; "default" values are the reference implementation's operator defaults and MAY differ.

| Parameter (`lookup::Config` field) | Value | Kind |
|---|---|---|
| `namespace` | `union_unique(b"TEMPO", b"_P2P")` = `0x05 \|\| "TEMPO" \|\| "_P2P"` = bytes `05 54 45 4d 50 4f 5f 50 32 50` | normative |
| stream namespace (derived by `lookup`) | `namespace \|\| b"_STREAM"` | normative (fixed by commonware) |
| `crypto` | the validator's ed25519 private key | normative |
| `max_message_size` | `8_388_608` bytes (reth `MAX_RLP_BLOCK_SIZE`) | normative lower bound: a node MUST accept application payloads up to this size; see 3.5 |
| `tracked_peer_sets` | 1 | default (see 2.4) |
| `max_peers_per_set` | 128 (distinct identities including self; registering a larger set is fatal) | default; an implementation MUST support at least the number of identities that 2.4 derives |
| `synchrony_bound` | 5 s | default |
| `max_handshake_age` | 10 s | default |
| `handshake_timeout` | 5 s | default |
| `dial_timeout` | 15 s | default |
| `max_concurrent_handshakes` | 512 | default |
| `allowed_handshake_rate_per_ip` | one per 5 s | default |
| `allowed_handshake_rate_per_subnet` | one per 15 ms | default |
| `peer_connection_cooldown` | 60 s | default |
| `dial_frequency` | 1 s | default |
| `ping_frequency` | 50 s | default |
| `block_duration` (how long a blocked peer stays blocked) | 4 h | default |
| `send_batch_size` | 8 | default |
| `bypass_ip_check` | false | default |
| `allow_private_ips` | false | default |
| `allow_dns` | true | default (ingress values from ValidatorConfigV2 are always literal socket addresses, so DNS is never used) |
| `listen` | operator-chosen (reference default `127.0.0.1:8000`; production nodes bind the port of their registered ingress) | default |

The handshake, key exchange, encryption and framing are those of `commonware_stream::encrypted` 2026.9.0 as driven by `lookup`; this chapter does not restate them. A connection is authenticated to an ed25519 public key; the application sees every inbound message tagged with that key.

On the authenticated stream, each frame carries a `lookup::types::Message`:

```
Message := 0x00 || Data          ; application data
         | 0x01                  ; Ping
Data    := varint(channel) || bytes(payload)
```

`channel` is the channel id of section 3 (a u64). `payload` is the channel's application message. Pings are transport keep-alives.

Reference implementation: crates/consensus/src/lib.rs (`instantiate_network`), crates/consensus/src/args.rs (defaults), crates/consensus/src/config.rs.

### 2.3 Peer addresses and admission

Each peer in a tracked set has a commonware `Address::Asymmetric { ingress, egress }` built from its ValidatorConfigV2 entry:

- `ingress` = `Ingress::Socket(parse_socket_addr(entry.ingress))` — the address other validators dial. `entry.ingress` is a string `"<ip>:<port>"` (IPv6 as `"[<ip>]:<port>"`) parsed with the Rust `std::net::SocketAddr` grammar.
- `egress` = `(parse_ip_addr(entry.egress), port 0)` — only the IP is used: it is the source address the peer's outbound connections come from.

An entry whose `publicKey` is not a valid ed25519 point encoding, or whose `ingress` or `egress` fails to parse, is *undecodable* (2.4 says how undecodable entries are handled).

Admission rules of `lookup` (normative behaviour of the reference implementation):

1. Outbound dials go only to **primary** peers, at their ingress address.
2. Inbound connections are accepted only from identities in the union of the primary and secondary peers of the tracked set(s).
3. Unless `bypass_ip_check` is set, an inbound connection whose source IP is not one of the registered egress IPs (of any primary or secondary peer) is rejected before the handshake.
4. Unless `allow_private_ips` is set, connections from or to non-global IP addresses are rejected.
5. Messages sent to `Recipients::All` go to every connected primary and secondary peer.

### 2.4 Peer-set derivation

Peer sets are derived only from finalized state. The node keeps the highest finalized tip that consensus (marshal) has reported, `consensus_tip`, initialised from the finalization archive tip at startup.

```python
def refresh_peers(el, consensus_tip_height, last_tracked):
    # Highest height that is both finalized in the EL and finalized by consensus.
    h = min(el.finalized_block_number() or 0, consensus_tip_height)
    if last_tracked is not None and last_tracked.height >= h:
        return last_tracked                     # nothing new

    # Latest boundary block at or below h.
    if last(epoch(h)) == h:
        b = h
    elif epoch(h) == 0:
        b = 0
    else:
        b = last(epoch(h) - 1)
    outcome = OnchainDkgOutcome.decode(el.header_by_number(b).extra_data)   # MUST succeed

    primary_keys   = outcome.players                       # sorted set (07-consensus.md)
    secondary_keys = [k for k in outcome.next_players if k not in primary_keys]

    # All contract reads below are against the post-state of block h.
    vc = ValidatorConfigV2.at_post_state(el.header_by_number(h))
    active = {}                                            # public key -> Address
    for entry in vc.getActiveValidators():
        d = decode(entry)                                  # see 2.3
        if d is None:
            continue                                       # undecodable active entries are skipped
        active[d.public_key] = d.address                   # a later duplicate replaces an earlier one

    primary = {}
    for k in primary_keys:
        if k in active:
            primary[k] = active.pop(k)
        else:
            d = decode(vc.validatorByPublicKey(k))         # inactive DKG player
            assert d is not None                           # invariant; violation is fatal
            primary[k] = d.address
    for k in secondary_keys:
        if k not in active:
            d = decode(vc.validatorByPublicKey(k))
            assert d is not None                           # invariant; violation is fatal
            active[k] = d.address
    secondary = active                                     # next players + other active validators
    return track_or_overwrite(h, primary, secondary, last_tracked)
```

`track_or_overwrite`:

- If nothing was tracked before, or the key sets of `primary` or `secondary` differ from the last tracked set, the node MUST track a new peer set with index `h` (`AddressableManager::track(h, {primary, secondary})`). With `tracked_peer_sets = 1` the previous set is dropped, disconnecting peers that left the union.
- If only addresses changed, the node MUST overwrite the addresses of the existing set in place (`AddressableManager::overwrite`).
- In all cases the remembered height becomes `h`.

When peer sets are refreshed:

1. Once at engine construction, from EL state alone, **before** marshal, the executor or the DKG manager start (the DKG manager may need peers to recover and authenticate the tip). If this initial read fails (missing header or state), startup MUST fail.
2. On every marshal `Update::Block` (the block is acknowledged immediately) and `Update::Tip`, after raising `consensus_tip` to the reported height if higher.
3. Every 30 s when no update arrived (the timer restarts on each update). Errors on these later refreshes are ignored; the previous set stays in force.

Consequences that implementers MUST preserve:

- Peer membership follows the DKG outcome of the latest finalized boundary (current players are always dialed) plus the contract's active set at the finalized tip (joining validators are reachable before they become players).
- Addresses always come from ValidatorConfigV2 at the finalized tip, including for players that are no longer active.
- A node whose EL is behind its consensus tip derives peers from the EL's finalized height. A node whose EL is ahead derives them from the consensus tip.

> **Note**: ValidatorConfigV2 has no entries before it is populated after T2 (mainnet genesis allocates only the V1 contract at `0xCCCCCCCC00000000000000000000000000000000`). The invariant assertions above therefore fail for heights before ValidatorConfigV2 holds entries for every player of the latest boundary outcome, so a validator cannot start its consensus engine from such a height; see 5.6.

> **TODO**: the lowest mainnet height at which ValidatorConfigV2 held a decodable entry for every player of the latest boundary outcome (the lowest height from which a validator-mode node can start) was not determined from the code; it depends on when the T2 migration populated the contract on mainnet.

Reference implementation: crates/consensus/src/peer_manager/{mod.rs,actor.rs}, crates/consensus/src/validators.rs.

### 2.5 Misbehaviour and blocking

Components that detect Byzantine behaviour from an authenticated peer (an invalid certificate or signature, an undecodable message on a channel, a resolver response that fails verification) block the peer through the `lookup` oracle (`Blocker::block`): the connection is dropped and the peer is refused for `block_duration` (4 h by default). A node MUST NOT block a peer for a certificate it cannot verify only because it lacks the epoch's scheme; in particular schemes MUST be retained for the two most recent epochs after an epoch ends (07-consensus.md), because straggling peers keep re-proposing and certifying the outgoing epoch's boundary block.

## 3. Consensus channels

### 3.1 Channel map

| Id | Name | Per-peer quota (inbound and outbound, each direction independently) | Epoch-multiplexed | Payload |
|---|---|---|---|---|
| 0 | votes | 128 msg/s | yes | `commonware_consensus::simplex::types::Vote<S, Digest>` |
| 1 | certificates | 128 msg/s | yes | `commonware_consensus::simplex::types::Certificate<S, Digest>` |
| 2 | simplex resolver | 128 msg/s | yes | `commonware_resolver::p2p::wire::Message<commonware_utils::sequence::U64>` (3.3.3) |
| 3 | block broadcast | 8 msg/s | no | consensus block encoding (3.3.4) |
| 4 | marshal backfill | `--consensus.backfill-frequency` msg/s, default 8 | no | `commonware_resolver::p2p::wire::Message<marshal::resolver::handler::Key<Digest>>` (3.3.5) |
| 5 | DKG | 128 msg/s | yes | Tempo DKG message (3.3.6) |

`S` is `bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>`. Quotas are `governor` GCRA quotas (burst = rate) enforced per channel and per peer by `lookup`; messages over quota are dropped (outbound sends fail). Quotas are local policy but a node that sends above its peers' quotas will see messages dropped; a conforming node SHOULD NOT exceed them.

Reference implementation: crates/consensus/src/config.rs, crates/consensus/src/lib.rs (`run_consensus_stack`).

### 3.2 Epoch multiplexing

Channels 0, 1, 2 and 5 are multiplexed by epoch with `commonware_p2p::utils::mux`: the channel payload is

```
MuxedPayload := varint(epoch) || inner_message
```

A node registers subchannel `E` on channels 0, 1 and 2 when it enters epoch `E` (starts the Simplex instance for `E`), and on channel 5 when its DKG manager runs the ceremony of epoch `E`. Messages for a subchannel that is not registered are dropped, except on channel 0 (votes), whose unregistered-epoch messages go to a backup handler:

```python
def on_vote_for_unregistered_epoch(their_epoch, sender):
    if no epoch has been entered yet:
        return
    reference = latest entered epoch
    if their_epoch <= reference:
        return
    # A peer votes in a later epoch: the boundary of our epoch must be finalized.
    marshal.hint_finalized(height=last(reference), targets=[sender])
```

The hint makes marshal fetch the finalization of `last(reference)` (with its block) from the sender (3.3.5). Once the DKG manager processes that finalized boundary block it enters the next epoch; this repeats one epoch at a time until the node reaches the network's epoch (5.5).

When a node exits epoch `E` (at the first finalized block of epoch `E+1`, 07-consensus.md) it deregisters `E`'s subchannels and deletes the scheme of epoch `E−2`.

### 3.3 Channel payloads

All payloads are commonware codec encodings of the pinned types.

#### 3.3.1 Channel 0: votes

`Vote<S, Digest>` (notarize, nullify, finalize) of commonware 2026.9.0 `simplex::types`, under the mux prefix. Signing domains and verification: 07-consensus.md.

#### 3.3.2 Channel 1: certificates

`Certificate<S, Digest>` (notarization, nullification, finalization) under the mux prefix. Informative summary (normative layout: 07-consensus.md §7): a finalization's encoding is `Proposal || vrf::Certificate` where `Proposal = varint(epoch) || varint(view) || varint(parent_view) || digest[32]` and `vrf::Certificate = vote_signature[48] || seed_signature[48]` (compressed G1 points), as in the golden frame of 4.3.4.

#### 3.3.3 Channel 2: simplex resolver

The Simplex resolver (commonware `simplex::actors::resolver`) fetches certificates for views a node missed. Wire message (`commonware_resolver::p2p::wire::Message<K>`):

```
Message := u64be(id) || Payload
Payload := 0x00 || Key            ; Request
         | 0x01 || bytes(value)   ; Response (same id as the request)
         | 0x02                   ; Error
```

For channel 2, `Key = U64(view)` (8-byte big-endian view number) and a response value is the encoding of a `Certificate<S, Digest>` (a nullification, notarization or finalization covering that view). Timeouts: requests are retried after `--consensus.wait-for-peer-response` (default 2 s).

#### 3.3.4 Channel 3: block broadcast

Channel 3 carries the commonware `broadcast::buffered` engine. Each message is exactly one consensus block encoding (the raw block RLP), not epoch-multiplexed and not otherwise framed. The leader broadcasts its proposed block to all peers (sent with priority). Receivers decode it (rejecting body/header mismatches and BAL hashes, section 0), cache it keyed by its digest (at most `--consensus.deque-size` = 10 digests per peer), and hand it to marshal and to the application for verification. A block received on channel 3 has no authority by itself; it becomes final only through a finalization (07-consensus.md).

#### 3.3.5 Channel 4: marshal backfill

Channel 4 carries the marshal resolver (`commonware_consensus::marshal::resolver::p2p`, built on `commonware_resolver::p2p`) with the wire message of 3.3.3 and the key:

```
Key := 0x00 || digest[32]                       ; Block: a block by hash
     | 0x01 || varint(height)                   ; Finalized: the finalization at a height, with its block
     | 0x02 || varint(epoch) || varint(view)    ; Notarized: the notarization of a round, with its block
```

Response values:

| Request | Response value | Requester MUST check |
|---|---|---|
| `Block(d)` | block encoding | decodes; `keccak256(rlp(header)) == d` |
| `Finalized{h}` | `enc(Finalization) \|\| enc(Block)` | the finalization verifies under the scheme of its epoch (07-consensus.md); its payload equals the block hash; the block's number is `h` |
| `Notarized{r}` | `enc(Notarization) \|\| enc(Block)` | the notarization's round is `r` and it verifies under the scheme of `r.epoch`; its payload equals the block hash |

A response that fails these checks SHOULD cause the requester to block the responder (2.5) and retry with another peer. Resolver parameters (reference): request timeout 2 s, retry delay 100 ms, requests and responses not sent with priority, peers chosen from the tracked peer set.

#### 3.3.6 Channel 5: DKG

Under the mux prefix (subchannel = the ceremony's epoch):

```
DkgMessage := 0x00 || DealerPubMsg<MinSig> || DealerPrivMsg   ; dealer -> one player
            | 0x01 || PlayerAck<ed25519::PublicKey>           ; player -> its dealer
```

The types are those of `commonware_cryptography::bls12381::dkg::feldman_desmedt` 2026.9.0. Every DKG message is sent to exactly one recipient, with priority. Semantics, validity and when to send: 07-consensus.md §9.3 "DKG messages".

### 3.4 Message size limits

- A node MUST NOT send an application payload (including the mux prefix) larger than its configured `max_message_size` (default 8,388,608 bytes). The reference implementation drops such an outbound message and counts it, instead of passing it to the transport.
- Inbound frames larger than the receiver's `max_message_size` are rejected by the transport.
- A proposed block travels as a single channel-3 message and inside channel-4 responses. Every node MUST accept inbound application payloads of at least 8,388,608 bytes (the block RLP size limit `MAX_RLP_BLOCK_SIZE` of EIP-7934, 05-block-execution.md). With the reference default (`max_message_size = 8,388,608`) a channel-4 response carrying a block whose RLP is within a few hundred bytes of that limit exceeds the limit once the finalization and `Message` framing are added, and is dropped by the responder; such a block can still be obtained from the EL (devp2p) or after a retry from a peer configured with a larger limit. Operators SHOULD NOT lower the default.

Reference implementation: crates/consensus/src/network.rs.

## 4. Execution-layer devp2p

### 4.1 Stack

Every Tempo node (validator or follower) runs reth's devp2p stack at the pinned revision:

- **Discovery**: discv4 (reth default). Mainnet bootnodes are compiled into the chain spec (informative list: crates/chainspec/src/bootnodes.rs, `PRESTO_BOOTNODES`; Moderato: `MODERATO_BOOTNODES`).
- **Transport**: RLPx with the `p2p` hello handshake. The node advertises `eth/66` through `eth/71` (reth `EthVersion::ALL_VERSIONS`) and, when enabled, `tempo/1` (4.3).
- **`eth` Status**: network id and chain id 4217 on mainnet (42431 on Moderato), genesis hash of the Tempo genesis (04-state-and-genesis.md), and the EIP-2124 fork id computed over Tempo's fork schedule as specified in 01-chain-and-forks.md. Peers whose fork id is incompatible are disconnected.

A conforming node MUST support at least one `eth` version that reth at the pinned revision accepts (`eth/68` or `eth/69` is RECOMMENDED) so that it can exchange transactions and serve and download headers and bodies.

### 4.2 What devp2p is used for

| Use | Messages | Notes |
|---|---|---|
| Transaction propagation | `Transactions`, `NewPooledTransactionHashes`, `GetPooledTransactions`/`PooledTransactions` | Tempo transaction envelopes (06-transactions-and-fees.md). Pool policy never affects block validity. |
| Serving and downloading history | `GetBlockHeaders`/`BlockHeaders`, `GetBlockBodies`/`BlockBodies` (and receipts) | Used by reth's own sync pipeline when a forkchoice update names a block the EL does not have, and by followers to fetch a block by hash (7.3). |
| Block propagation | none | `NewBlock`/`NewBlockHashes` are not used (post-merge semantics). Blocks reach the EL only through the engine API from the node's own CL. |

A node MUST NOT treat a block obtained over devp2p as canonical or final because a peer served it. Canonicality comes only from the CL's forkchoice updates, which are driven by verified finalization certificates (sections 7 and 8). Devp2p is an untrusted data source: a block fetched by hash is authenticated by that hash, which a verified certificate or a verified descendant committed to.

### 4.3 The `tempo/1` subprotocol

`tempo/1` is an RLPx capability that gossips finalization certificates between Tempo nodes. It lets a follower keep progressing when its upstream RPC is unavailable.

#### 4.3.1 Capability

| Item | Value |
|---|---|
| Capability name | `"tempo"` |
| Version | `1` |
| Message ids reserved | 1 (the capability's message-id space is offset by RLPx after all lower-sorting capabilities, as for any RLPx subprotocol) |
| Messages | `0x00` `NewFinalization` |
| Maximum frame size | 1,024 bytes (message id included) |

A node offering `tempo/1` MUST advertise it in every RLPx hello; capabilities are negotiated per session, so a session opened before the protocol was registered never carries it. If the remote side does not support `tempo/1`, the session MUST be kept for its other capabilities (`eth`).

The reference node offers `tempo/1` by default (`--consensus.devp2p.finalizations=true`).

#### 4.3.2 Frame format

A `NewFinalization` is carried as an RLPx message whose message id is the capability's base offset plus `0x00` and whose data (after snappy decompression, as for every RLPx message) is the raw certificate encoding. Expressed as the id-relative frame that the reference transport handles:

```
frame := 0x00 || enc(Finalization)
```

There is no RLP wrapping: `enc(Finalization)` is the commonware codec encoding of `Finalization<vrf::Scheme<ed25519::PublicKey, MinSig>, Digest>` (3.3.2). Decoding rules, in order:

1. `len(frame) > 1024` → oversized; the receiver MUST close the connection.
2. `len(frame) == 0` → empty; malformed.
3. `frame[0] != 0x00` → unknown message id; malformed.
4. `frame[1:]` does not decode as exactly one `Finalization` (no trailing bytes) → malformed.

The frame layout is frozen for version 1; an incompatible change MUST use a new version.

#### 4.3.3 Sender rules

- Validators and followers publish only finalizations that are stored in their own finalization archive (section 9): when marshal reports a new finalized tip `(round, height)`, the node reads the stored finalization at `height` and publishes it. If none is stored, nothing is published.
- A node keeps one **latest publication**, the frame with the highest round it has published. A tip whose round is lower than the latest publication's is not published. Republishing the same round reuses the cached frame bytes.
- Per logical peer the node tracks `seen_round`, the highest round it sent to or received from that peer. It MUST NOT offer a frame whose round is ≤ `seen_round`. On a new peer connection the latest publication (if any) is offered immediately.
- Outbound buffering keeps only the newest frame per logical peer; an unsent older frame is replaced.
- At most 2 concurrent physical RLPx connections per peer id are attached to the logical peer (a transient duplicate during reth's connection reconciliation); a third is rejected, which closes that RLPx connection.

#### 4.3.4 Golden frame

This 132-byte frame MUST round-trip (decode then encode yields the same bytes):

```
000001000000000000000000000000000000000000000000000000000000000000000001
893a6fba4f0630edd4f1f610258f9b3a1e1fbf9c1abefaea77a62bfd27b0dea1d448c4b4b992fa094bf96c8789b49cfa
8565f0bc98152e274fd6d0e3b85955736432cdca1a52201ff244bf69a65b566ffbcf642a53a23e66b4d9bd6819dd95cc
```

| Offset | Bytes | Field |
|---|---|---|
| 0 | `00` | message id `NewFinalization` |
| 1 | `00` | `proposal.round.epoch` = varint 0 |
| 2 | `01` | `proposal.round.view` = varint 1 |
| 3 | `00` | `proposal.parent` (parent view) = varint 0 |
| 4..35 | `00…01` | `proposal.payload` (32-byte digest) |
| 36..83 | `893a6f…49cfa` | `certificate.vote_signature` (48-byte compressed G1) |
| 84..131 | `8565f0…95cc` | `certificate.seed_signature` (48-byte compressed G1) |

The fixture only pins the layout; its signatures are not valid for any real network key.

#### 4.3.5 Receiver rules

A node ingests `tempo/1` frames only in certified follower mode. Validators MUST discard inbound `tempo/1` frames (they receive certificates over the authenticated consensus network); they still enforce the size limit.

Per physical connection, in order:

1. Oversized frame (> 1,024 bytes) → close the connection. Reth's ingress limit (1,024 bytes per frame, at most 64 buffered frames and 64 KiB buffered per connection) applies before decompression.
2. Per-connection admission rate limit: 8 frames/s (`--consensus.devp2p.finalizations.peer-frame-rate`); frames over the rate are dropped silently.
3. Not ingesting (validator) → drop.
4. Enqueue to consensus; the shared queue holds 256 frames and drops on overflow (a later certificate also finalizes earlier blocks, so a loss does not block progress).

In the consensus-side actor, per logical peer:

1. Frame from a peer with no live connection → drop.
2. Malformed (4.3.2 rules 2–4) → drop and penalize the peer (reth reputation change `BadMessage`).
3. `round ≤ seen_round(peer)` → replay, drop. Otherwise set `seen_round(peer) = round`.
4. `round ≤ latest_verified_round` (the highest round verified locally or stored by marshal) → stale, drop.
5. Put the certificate in the peer's single **slot**, replacing a slot that is still waiting (keeping its queue position); if the peer's slot is being verified or quarantined, drop the new frame.
6. Verification is dispatched one certificate at a time, from the slot that has waited longest, at most 32 per second across all peers (`--consensus.devp2p.finalizations.verify-rate`). The verifier is the follower driver (7.4, `process_certificate`). Results:
   - **valid**: raise `latest_verified_round`; clear every slot whose round is ≤ it; the certificate is reported to marshal as a finalization (marshal then fetches its block and, once stored, republishes it per 4.3.3).
   - **invalid** (verification failed under a scheme learned from an authenticated boundary): clear every slot holding the identical frame bytes (compared by `keccak256(frame)`) and penalize each owning peer.
   - **needs scheme** (no scheme for the epoch yet, or it failed only against the pinned network identity fallback): quarantine the slot until a finalized boundary block installs a scheme for that epoch, then requeue it. The sender is not penalized.
   - **no answer** (verifier unavailable): settle the frame (clear identical slots) without penalty.

Reference implementation: crates/node/src/gossip/{wire.rs,transport.rs,peer_control.rs}, crates/consensus/src/gossip/{actor.rs,ingress.rs,mod.rs}.

## 5. Backfill and sync

### 5.1 Storage model

Validators and followers keep the same consensus storage (so a node can switch modes without migration, 9.5):

- **Finalizations by height**: an immutable archive (`commonware_storage::archive::immutable`) mapping height → `Finalization`, keyed also by block digest. It holds one finalization per finalized height from the node's floor upward (heights for which only a later descendant's certificate was received may be absent). The genesis block MUST NOT have a finalization. Validators never prune it.
- **Finalized blocks**: a *hybrid* store. A prunable archive (`commonware_storage::archive::prunable`, 4,096 items per section) holds recently finalized blocks; every block at or below the EL's finalized height is served from the EL (canonical blocks only). On every insertion the prunable archive drops whole sections below `el_finalized − retention + 1` (default retention 64,800 = 3 × 21,600 blocks, so it holds between 64,800 and 68,895 blocks once the EL has caught up). It never drops a block the EL has not finalized. Gap tracking treats every height at or below the EL's finalized height as present.
- **Marshal metadata**: the last processed (delivered and acknowledged) height and marshal's floor.

### 5.2 Gap repair

Marshal delivers finalized blocks to the application strictly in height order without gaps, at least once each. When it knows a finalization (or a finalized tip) at height `t` above its last contiguous height `c`:

1. If the block named by the finalization is missing, it requests `Block(payload)`.
2. Having a block at height `h > c + 1` whose parent is missing, it requests `Block(parent_hash)`, walking parent hashes downward until it reaches height `c + 1`. Each fetched block is authenticated by the hash its child committed to; it is stored as finalized because a verified finalization of a descendant finalizes all ancestors.
3. A **hint** `hint_finalized(h, targets)` requests `Finalized{h}` from the given peers; the response carries the finalization and block for `h`, verified per 3.3.5.

Requests go over channel 4 (validators) or to the follower resolver (7.3). At most 20 blocks are repaired per repair round (reference `max_repair`). Requests below marshal's floor are cancelled.

### 5.3 Serving obligations

A validator MUST answer channel-4 requests it can satisfy:

- `Block(d)` from the prunable archive or, for canonical EL blocks, from the EL;
- `Finalized{h}` for any height in its finalization archive, with the block from the hybrid store;
- `Notarized{r}` for rounds still in marshal's in-memory cache (`view_retention` = 10 × `--consensus.views-to-track` = 2,560 views by default).

It answers `Error` (or nothing) when it cannot. A node whose EL prunes history can serve blocks only within its retention window; requests for heights below it fail without penalty and the requester retries elsewhere.

### 5.4 Retention guarantees

| Data | Reference retention | Guarantee a peer can rely on |
|---|---|---|
| Finalized blocks in the prunable archive | ≥ 64,800 blocks behind the EL's finalized tip (`MINIMAL_PEER_SYNC_FINALIZED_BLOCKS`, `--consensus.finalized-blocks-retention`) | blocks up to three mainnet epochs behind the finalized tip are servable from consensus storage |
| Finalized blocks older than that | served from the EL; available iff the EL has not pruned them (RPC/archive nodes default to archive mode; `--minimal` prunes) | none |
| Finalizations | the finalization archive is never pruned: a node keeps every finalization it stored from its first stored height (genesis+1 for a node synced from genesis, the snapshot anchor for a restored node) upward; heights finalized only implicitly (through a descendant's certificate during backfill) may lack one | validators that are not freshly restored hold the finalization of every height of the current and previous epoch and of every boundary they processed |
| DKG events | current and previous epoch | (local only) |

Validators SHOULD keep EL history for at least `MINIMAL_PEER_SYNC_FINALIZED_BLOCKS` blocks so that peers up to three epochs behind can catch up over consensus p2p.

### 5.5 Epoch catch-up (validators)

A validator that is behind enters epochs one at a time:

```python
while behind:
    E = latest entered epoch
    # Triggered by a vote for an epoch > E (3.2), or by marshal's own gap repair.
    marshal.hint_finalized(last(E))                    # fetch Finalized{last(E)} from the voter
    # The finalization of last(E) verifies under epoch E's scheme, which the node has.
    # Marshal backfills epoch E's blocks by parent hash and delivers them in order.
    # The DKG manager processes the finalized boundary block last(E), persists the
    # state for epoch E+1 (07-consensus.md) and only then enters epoch E+1, which
    # registers the scheme for E+1 and the channel subchannels for E+1.
```

A node MUST NOT install the scheme of epoch `E+1` before the boundary block `last(E)` is finalized and processed, and MUST NOT accept a hint target's claim about any other height: hints always name the boundary of the node's own current epoch.

### 5.6 Syncing from genesis

**Follower mode** syncs any history, including from genesis:

1. At genesis the EL's finalized height is 0, so the follower installs the epoch-0 scheme from the genesis outcome and pins the configured network identity (7.5).
2. It verifies the upstream's latest finalization against the pinned identity (mainnet: `from_epoch = 2042`) and reports it to marshal.
3. Marshal fetches the tip block and walks parent hashes down to height 1 (5.2), storing every block as finalized; blocks are delivered in order and executed by the EL (7.6). Historical certificates are not needed: the verified tip authenticates its whole ancestry by hash.

**Validator mode** derives peers from ValidatorConfigV2 at the finalized tip (2.4) and replays finalized blocks through the engine API with `VALID` required (8). A validator therefore cannot start consensus from a state whose finalized height precedes the population of ValidatorConfigV2 with entries for every player of the latest boundary outcome. To join from scratch, a validator MUST first reach a recent finalized height in follower mode or from a snapshot (section 6), then start in validator mode on the same storage (9.5).

In validator mode, on startup the executor first replays finalized blocks from the EL's finalized height up to marshal's finalized floor (from marshal storage, falling back to the EL), issuing a forkchoice update every 8 delivered blocks and at the floor, after waiting until the EL reports ready (a forkchoice update reaffirming the EL's own current forkchoice returns `VALID`, polled every 1 s). If a block in that range cannot be sourced, startup fails.

## 6. Consensus snapshots

A snapshot lets a node start from recent state instead of genesis. It consists of an execution-layer snapshot (reth's modular snapshot format and manifest) plus a consensus archive.

### 6.1 Contents

The snapshot manifest (reth `SnapshotManifest` JSON) carries an extension object under the key `"consensus"`:

| Field | Type | Meaning |
|---|---|---|
| `execution_finalized_height` | integer | the EL snapshot source's finalized height |
| `execution_finalized_digest` | 0x-hex 32 bytes | its block hash |
| `tip_finalization_height` | integer | the highest height with a finalization in the source |
| `tip_finalization_digest` | 0x-hex 32 bytes | that finalization's payload |
| `anchor_finalization_height` | integer | the anchor (6.2) |
| `anchor_finalization_digest` | 0x-hex 32 bytes | the anchor finalization's payload |
| `consensus_archive` | reth `SingleArchive` (`file`, `size`, `decompressed_size`, `blake3`, `output_files` with `path`, `size`, `blake3` each) | the consensus archive |

The manifest's EL snapshot block MUST be at or above `execution_finalized_height`.

The consensus archive `consensus.tar.zst` is a zstd-compressed tar of commonware storage partitions (blob layout V0) with these and only these partitions:

- `engine-finalizations-by-height-*` (metadata, freezer table, freezer key, freezer value, ordinal): every finalization from the anchor height to the tip height that the source holds;
- `engine-finalized-blocks-prunable-*` (key, value, metadata): every prunable-archive block above `execution_finalized_height`.

It excludes the DKG state, the follower identity record, Simplex vote journals and marshal metadata; a restored node rebuilds them (6.4).

### 6.2 Anchor selection

```python
def select_anchor(finalizations, prunable, el_finalized):
    tip = finalizations.last_index()                    # error if none
    candidate = tip
    while True:
        if candidate <= el_finalized:
            return candidate
        hole = highest height in (el_finalized, candidate] missing from prunable, or None
        if hole is None:
            return candidate                            # contiguous blocks from el_finalized+1 to candidate
        below = highest height < hole with a finalization, or None
        if below is None:
            raise "no anchor"
        candidate = below
```

So the anchor is the highest finalized height from which a contiguous run of snapshot blocks reaches down to the EL snapshot's finalized block, or a certified height at or below the EL's finalized height. A producer MUST NOT create a snapshot while the source node's consensus storage is in use.

### 6.3 Installation

Before replacing any local consensus data the installer MUST:

1. check the archive's blake3 hash against `consensus_archive.blake3`;
2. extract it into a staging directory without following or creating links outside it;
3. require that every top-level entry is a directory named with one of the two partition prefixes of 6.1, that every entry inside is a regular file, that every file is listed in `output_files` with matching size and blake3 hash, and that every listed file is present;

then move the partitions into the consensus data directory (default `<datadir>/consensus`), refusing to overwrite existing files unless forced.

These checks only protect integrity against the manifest. Authenticity comes from the startup checks of 6.4.

### 6.4 Trust: verifying a restored snapshot at startup

A node started on restored storage performs, before any actor runs:

1. **Archive consistency** (9.4): the finalization archive's tip certificate epoch equals `epoch(tip_height)`; its first index is not 0; the tip header, where the prunable archive or the EL has a block at that height, has number `tip_height` and hash equal to the tip certificate's payload.
2. **Floor verification**: the floor is the first finalization in the archive (the anchor). The node reads `header(boundary_for(cert.epoch))` from the hybrid store, decodes its `OnchainDkgOutcome`, requires `outcome.epoch == cert.epoch`, builds the full verifier scheme from `outcome.players` and `outcome.sharing`, and requires the floor finalization to verify. Failure is fatal. The scheme is registered for the floor's epoch.
3. **Tip verification against the trusted identity** (summary; normative rule: 07-consensus.md §8.3 "startup identity selection and tip check"): the trusted identity is the configured one (built-in: mainnet `{from_epoch: 2042, identity: 0x8627d337…a182}`, see 07-consensus.md), replaced by a persisted identity with a higher `from_epoch` (validators: from DKG state; followers: from the driver record, 9.3); a persisted identity with the same `from_epoch` but a different key is fatal. If the tip certificate's epoch ≥ `trusted.from_epoch` it MUST verify under the trusted identity, otherwise startup fails (an operator must configure a newer identity after a full-DKG rotation). If its epoch < `from_epoch` it is accepted as historical. The trusted identity is registered for `from_epoch`, and for the tip's epoch when verified; a later attempt to register a different key for either epoch is fatal.
4. **EL linkage**: when the floor is below the EL's finalized height, the executor starts from the EL's canonical block at the floor height and marshal re-delivers finalized blocks from the floor; each delivery must extend the EL's canonical chain (a `newPayload` that is not `VALID` for a finalized block is fatal, section 8). When the floor is above the EL's finalized height, the executor backfills from the EL's finalized height to the floor from the snapshot's contiguous prunable blocks (5.6).

The state root of the EL snapshot is thereby authenticated: it is in a header on the hash chain from the verified anchor/tip down to the EL's finalized block, and the EL executes every later finalized block on top of it.

After restore, the validator DKG manager has no persisted state and rebuilds it from the latest boundary outcome at or below the floor (07-consensus.md): its share comes, in order of preference, from `--consensus.signing-share` if it matches the outcome's public polynomial at its index, then from a salvaged stale share that matches, then by recovery from dealings revealed in the previous epoch's finalized dealer logs.

Reference implementation: crates/consensus/src/storage/{mod.rs,snapshot.rs,hybrid/mod.rs}, crates/consensus/src/alias.rs, crates/consensus/src/startup.rs, bin/tempo/src/{snapshot_manifest.rs,snapshot_download.rs}.

## 7. Follower mode

### 7.1 Model

A follower runs marshal, a *driver* that verifies certificates, a resolver that fetches missing data, and an executor that drives its EL; it runs no Simplex instance, no DKG and no consensus p2p. Its trust model is:

- **Trust root**: the network identity pinned in the node (built-in per chain, overridable with `--consensus.network-identity` + `--consensus.network-identity-from-epoch`), together with the identities it learns from finalized boundary blocks (07-consensus.md §8 "Trust chain and network identity").
- **Everything else is untrusted**: the upstream RPC node, `tempo/1` peers and devp2p peers only supply data; a follower accepts a block as finalized only if a finalization that verifies under a trusted scheme commits to it or to a descendant.

A follower executes every block in its EL; it does not trust the upstream's state.

### 7.2 Certificate sources

**Upstream JSON-RPC** (required in the reference implementation; `--follow <ws-url>` or `--follow auto`, which uses `wss://rpc.presto.tempo.xyz` on mainnet and `wss://rpc.moderato.tempo.xyz` on Moderato). The follower uses a WebSocket connection (ping every 5 s, closed after 10 s of inactivity, reconnect backoff 2 s × attempts capped at 20 s plus up to 1 s jitter) and these methods (informative; RPC is out of scope of this specification):

| Method | Use |
|---|---|
| `consensus_subscribe` (notifications `event`) | stream of `Event` objects tagged by `"type"`: `"finalized"` (`CertifiedBlock` fields flattened plus `seen` ms), `"notarized"` (ignored), `"nullified"` (ignored) |
| `consensus_getFinalization(query)` | `query` is `"latest"` or `{"height": N}`; returns a `CertifiedBlock` |
| `eth_getBlockByHash(hash, true)` | full block by hash (block source, 7.3) |

`CertifiedBlock` = `{ epoch, view, digest, certificate, block }` where `certificate` is the hex encoding of `enc(Finalization)` and `block` is the full JSON block (header and transactions).

The reference feed emits only `"finalized"` events and always returns `notarized: null` from `consensus_getLatest`; a follower MUST NOT depend on notarized or nullified events.

> **Open conflict C-P2P-02**: docs protocol/rpc/index.mdx says `consensus_subscribe` emits notarized, finalized and nullified events and `consensus_getLatest` returns the latest notarized block; the code emits only finalized events and always returns `notarized: null`. See [conflicts](conflicts.md#c-p2p-02).

**`tempo/1` peers** (optional, on by default): frames verified per 4.3.5 and 7.4.

An implementation without RPC MAY rely on `tempo/1` alone as its certificate source; a `tempo/1` certificate only names a block hash, which the follower then fetches (7.3). Such a follower can verify only certificates whose epoch scheme it already installed or that verify under its pinned identity: it fetches blocks by hash over devp2p, but crossing a full-DKG rotation it slept through needs a source of `Finalized{h}` for the intermediate boundaries (an upstream) or an updated pinned identity.

### 7.3 Block sources

When marshal needs a block by hash the follower resolver tries, in order:

1. its own EL (any block the EL has, canonical or not);
2. otherwise it races the upstream (`eth_getBlockByHash`) against devp2p (a full-block request by hash: `GetBlockHeaders` for the hash, then `GetBlockBodies`), taking the first that returns.

When marshal needs `Finalized{h}` (a hint) the follower asks the upstream `consensus_getFinalization({"height": h})` and returns `(finalization, block)` to marshal for verification. Every fetched block MUST be checked for body/header consistency and the absence of a BAL hash before use, and its hash MUST equal the requested hash. Each request has a deadline (`--follow.upstream-request-timeout`); failed keys are retried with exponential backoff from 250 ms, doubling up to 30 s. `Notarized` requests are never resolved in follow mode.

### 7.4 Verification

```python
# scheme_provider: epoch -> verifier scheme; a second registration for an epoch with a
# different network identity is fatal. Pinned at startup with the trusted identity (7.5).

# Normative verification and identity chaining: 07-consensus.md §7-§8; restated here for the follower flow.
def verify_certificate(fin):
    E = fin.round.epoch
    if scheme_provider.has(E):
        if not fin.verify(scheme_provider[E]):          # 07-consensus.md
            return INVALID                              # sender is at fault
        return OK
    if E >= trusted.from_epoch:
        s = certificate_verifier(NAMESPACE=b"TEMPO", identity=trusted.identity)
        if not fin.verify(s):
            return FALLBACK_FAILED                      # identity may have rotated
        scheme_provider.register(E, s)
        return OK
    return IDENTITY_UNAVAILABLE

def decode_and_verify(certified_block):                 # upstream path
    check body matches header
    fin = Finalization.decode(hex_decode(certified_block.certificate))   # malformed -> error
    require fin.proposal.payload == certified_block.block.hash
    require fin.round.epoch == epoch(certified_block.block.number)
    return verify_certificate(fin)
```

Handling:

- Upstream event, `OK`: report the block to marshal as certified for `fin.round` and report `fin` as a finalization.
- Upstream event, `FALLBACK_FAILED`: if `epoch(block.number) > current_epoch`, set `epoch_sync_target` to the max of it and any pending target and hint the boundary of the current epoch (7.5). Drop the event.
- Upstream event, `INVALID`: drop. Other errors (malformed, digest or epoch mismatch): drop and log.
- `tempo/1` certificate with `round ≤ latest_verified_round`: accept as already settled. `OK`: raise `latest_verified_round` and report the finalization to marshal (marshal fetches the block). `INVALID` → *invalid*. `IDENTITY_UNAVAILABLE` → *needs scheme*. `FALLBACK_FAILED` → hint as above, then *needs scheme* (4.3.5).

`current_epoch` is the highest epoch whose scheme the follower has installed from an authenticated boundary.

### 7.5 Identity installation

At startup (after marshal is initialized):

1. Run the tip verification of 6.4 step 3 with the persisted driver identity (9.3).
2. Let `f` be the EL's finalized height and `b` the latest boundary at or below `f` (`f` itself if it is a boundary, else `last(epoch(f) − 1)`, or 0). Decode `header(b).extra_data` as an `OnchainDkgOutcome` (failure is fatal) and register `certificate_verifier(outcome.network_identity)` for `outcome.epoch`. Set `current_epoch = outcome.epoch`.
3. If marshal's finalized floor is in a later epoch than `b`'s outcome describes (the EL is behind consensus storage), let `p = epoch(floor) − 1`; if `p > epoch(b)` and marshal has the block `last(p)`, decode and register its outcome likewise and raise `current_epoch`. If marshal lacks it, continue: the node relies on the pinned identity fallback.

On every block marshal delivers (in order, after durable storage), if it is a boundary block `last(E)`:

```python
outcome = OnchainDkgOutcome.decode(block.extra_data)       # MUST succeed
scheme_provider.register(outcome.epoch, certificate_verifier(outcome.network_identity))
assert outcome.epoch == E + 1                               # fatal otherwise
if outcome.epoch >= configured.from_epoch and outcome.network_identity != configured.identity:
    warn("binary's network identity is outdated")
persisted_from = max(trusted.from_epoch, driver_record.from_epoch if any)
if outcome.epoch >= persisted_from:
    driver_record.observe(from_epoch=outcome.epoch, identity=outcome.network_identity)
current_epoch = max(current_epoch, outcome.epoch)
if epoch_sync_target is not None:
    if current_epoch >= epoch_sync_target: epoch_sync_target = None
    else: marshal.hint_finalized(last(current_epoch))         # one boundary at a time
acknowledge(block)                                          # always last
```

`driver_record.observe` persists `{from_epoch, identity}` only when the identity differs from the persisted one (a reshare keeps the original `from_epoch`), syncing before returning.

A hint always names `last(current_epoch)`, never a height taken from an unverified certificate. Each processed boundary installs the scheme needed to verify the next boundary's finalization, so a follower that slept through a full-DKG rotation catches up one epoch at a time; a quarantined `tempo/1` certificate is retried once a processed boundary installs its epoch's scheme. Gossip observes boundaries only after the driver has processed them.

### 7.6 Driving the EL (followers)

Marshal reports finalized tips (`Update::Tip(round, height, digest)`, sent only once that finalization is stored) and delivers finalized blocks in order (`Update::Block`) to the follower executor, which processes one request at a time, blocks before tips.

A forkchoice **target** is `(round?, hash)`. A delivered block's target takes its round from the header's consensus context (present from TIP-1031 activation, 07-consensus.md; absent in earlier headers); a tip's target always has a round. `a.supersedes(b)` is `a.round > b.round` when both have a round, true when only `a` has one, and false otherwise. `live` is the target of the EL's current finalized header.

```python
def on_block(block):
    status = engine_newPayload(block)
    if status not in (VALID, SYNCING):
        fatal()
    t = target(block)
    if not (live().supersedes(t) or not t.supersedes(live())):
        forkchoice(t)
    marshal.acknowledge(block)          # also after SYNCING
    last = max_by_supersedes(last, t)

def on_idle():
    if latest_tip.hash != last.hash and latest_tip.supersedes(last):
        if not live().supersedes(latest_tip):
            forkchoice(latest_tip)
        last = latest_tip

def forkchoice(t):
    r = engine_forkchoiceUpdated(head=t.hash, safe=t.hash, finalized=t.hash, attributes=None)
    if r is error TooDeepReorg and live().supersedes(t):
        return                           # the EL finalized past the target meanwhile
    if r is any other error or r.status == INVALID:
        fatal()
```

So blocks without a round (before TIP-1031) are only delivered with `newPayload`; the EL is moved by the next tip, whose target always has a round. A heartbeat resends a forkchoice to the latest tip every `--consensus.fcu-heartbeat-interval` (default 5 min) of inactivity.

**Floor advance**: after each completed request, if a tip was reported since the last advance (the first such tip's height is the *floor candidate*), the candidate is ≤ `el_finalized − epochLength`, and the EL has durably persisted the candidate block, the executor sets marshal's floor to the stored finalization at the candidate height.

A follower's `head`, `safe` and `finalized` are always the same finalized block; followers never expose unfinalized blocks.

### 7.7 Uncertified follow mode (informative)

`--follow.nocertify` runs reth's debug consensus client against the upstream without certificate verification. Such a node trusts the upstream completely and is not a conforming follower.

Reference implementation: crates/consensus/src/follow/{engine.rs,driver/,resolver/,upstream/,executor/}, crates/consensus/src/finalization_verifier/mod.rs, crates/consensus/src/epoch/scheme_provider.rs, crates/node/src/rpc/consensus/.

## 8. Driving the EL (validators)

The validator executor separates **delivery** from **forkchoice**:

- `engine_newPayload` delivers a block and never moves the head. Notarized blocks, finalized blocks and verification probes are all deliveries.
- `engine_forkchoiceUpdated` (outside block building) sets `finalized = safe =` the latest delivered finalized block, and `head =` the *convergence target* (the parent selected by the latest consensus context, i.e. the notarized tip being built on) only if that target's own `newPayload` returned `VALID` and its ancestry was walked down to the current finalized tip; otherwise `head =` the finalized block.
- A finalized block whose `newPayload` is not `VALID`, a forkchoice update that is not `VALID`, and any engine call that fails outright are fatal.
- A finalized block is acknowledged to marshal only once the forkchoice update finalizing it was accepted **and** the EL has durably persisted it.
- Block building: fetch and deliver the parent, then `forkchoiceUpdated` with payload attributes on `VALID`. Verification probes and the `SYNCING` ancestor walk are specified in 07-consensus.md (validator verification procedure).
- A heartbeat forkchoice update is resent after `--consensus.fcu-heartbeat-interval` (default 5 min) without one.

So on a validator, the EL's `finalized`/`safe` tags are the latest finalized block and `latest` is the notarized tip the node is converging on, which is never behind `finalized`.

Reference implementation: crates/consensus/src/executor/{mod.rs,actor.rs}.

## 9. Persistence and crash safety

### 9.1 Storage layout (reference)

All consensus storage lives under the consensus data directory (`--consensus.datadir`, default `<datadir>/consensus`), as commonware runtime storage partitions (blob layout V0). `P = "engine"`.

| Partition(s) | Content | Used by | In snapshot |
|---|---|---|---|
| `P-finalizations-by-height-{metadata,freezer-table,freezer-key,freezer-value,ordinal}` | finalizations by height | validator, follower | yes |
| `P-finalized-blocks-prunable-{key,value,metadata}` | recent finalized blocks | validator, follower | yes |
| marshal's internal partitions under prefix `P` | processed height, floor | validator, follower | no |
| `P_epoch_manager_consensus_epoch_<E>` | Simplex journal of epoch `E` (own votes and observed artifacts) | validator | no |
| `P_dkg_manager_states_metadata` | DKG `State` per epoch (key `u64` epoch) | validator | no |
| `P_dkg_manager_events` | DKG event journal, one section per epoch | validator | no |
| `P_driver_states_metadata` | follower trusted-identity record (key `0`) | follower | no |

### 9.2 Validator requirements

A validator MUST satisfy all of the following across crashes and restarts:

1. **No equivocation.** Before sending a Simplex vote it MUST durably record it in the epoch's journal, and on restart it MUST replay the journal and never send a conflicting vote for a view it already voted in (07-consensus.md). Losing a journal (for example by restoring a snapshot, which never contains journals) while the epoch is still running risks equivocation; an operator MUST NOT run a validator whose journal for the current epoch was lost unless it is certain it sent no vote in that epoch's remaining views.
2. **DKG consistency.** It MUST durably persist, before acting on them: the per-epoch DKG `State` (`epoch`, transcript `seed`, `output`, `share`, `players`, an empty legacy `syncers` set, `is_full_dkg`) when it enters an epoch; every dealing it received as a player (so it never acknowledges two different dealings from one dealer); every acknowledgement it received as a dealer; every dealer log read from a finalized block; and finalized-block markers. It MUST NOT acknowledge differently after a restart. Events of epochs older than the previous one MAY be pruned.
3. **Ack after durability.** A finalized block MUST NOT be acknowledged to marshal (and so marked processed) until the EL has durably persisted it and accepted the forkchoice update finalizing it; marshal emits a block only after durably storing it with its finalization. On restart, marshal resumes delivery above `max(stored processed height, finalization-archive floor)`, and the executor first replays blocks from the EL's finalized height up to that point (5.6), so no finalized block is skipped by the EL.
4. **Startup checks** of 9.4 MUST pass before any actor starts.

DKG state format (commonware codec): `State := varint(epoch) || seed[32] || Output<MinSig, ed25519> || ShareState || Set<ed25519>(players, 1..=65535) || Set<ed25519>(syncers, 0..=65535, always empty) || bool(is_full_dkg)`; `ShareState := 0x00 || Option<Share>` (plaintext; other tags are reserved). Event journal entries: `0x00 || dealer || DealerPubMsg || DealerPrivMsg` (dealing), `0x01 || player || PlayerAck` (ack), `0x02 || dealer || DealerLog` (log), `0x03 || digest[32] || parent[32] || varint(height)` (finalized). These are local formats; only their durability semantics are normative.

On startup the DKG manager uses the persisted state if its epoch is at least the epoch of height `floor + 1`; otherwise it rebuilds the state from the chain as described at the end of 6.4.

### 9.3 Follower requirements

1. Marshal storage and the ack-after-processing rule as for validators, except that a follower acknowledges a block once its `newPayload` returned `VALID` or `SYNCING` and its forkchoice update was handled; the floor only advances to blocks the EL has durably persisted and that are at least one epoch behind the EL's finalized height (7.6).
2. The trusted-identity record: `StoredIdentity := 0x01 || u64be(from_epoch) || G2[96]` (version 1; 105 bytes; other versions are rejected), stored under key 0, written with a durable sync when the identity changes (7.5). It is never part of a snapshot.
3. A follower MUST NOT move its EL forkchoice to a block that marshal has not stored together with its finalization (or as an ancestor of a stored finalization).

### 9.4 Startup consistency checks (both modes)

In order; any failure is fatal:

1. The finalization archive's tip certificate epoch equals `epoch(tip_height)`.
2. If the archive is empty, the EL's finalized height MUST be 0 (genesis start). If one of first/last index is set the other MUST be too. The first index MUST NOT be 0.
3. The tip header found at `tip_height` in the prunable archive and, separately, in the EL (each only if present) MUST have number `tip_height` and hash equal to the tip certificate's payload.
4. If the floor is above genesis, the archive MUST contain the floor's finalization, and it MUST verify under the scheme built from the outcome at `boundary_for(floor.epoch)` (6.4 step 2).
5. The archive tip height MUST be ≥ marshal's stored processed height (otherwise consensus storage was overwritten with a stale snapshot).
6. Tip verification against the trusted identity (6.4 step 3); genesis MUST have no tip certificate and a tip MUST NOT be below the floor.
7. Validators: initial peer-set registration (2.4) MUST succeed.

### 9.5 Mode switching

Validators and followers use the same partition prefix and archive formats for marshal storage, so a node MAY stop in one mode and restart in the other on the same data directory. A follower that becomes a validator also needs its ed25519 key, and either a share for the current epoch or recovery per 6.4.

## 10. Key and share files (informative)

| File | Format |
|---|---|
| `--consensus.signing-key` (plaintext) | `0x`-prefixed (or bare) hex of the commonware encoding of the ed25519 private key (the 32-byte seed), surrounding whitespace ignored |
| `--consensus.signing-key` with `--consensus.secret <path>` | an age (age-encryption.org/v1) scrypt passphrase-encrypted file whose plaintext is the raw commonware-encoded ed25519 private key bytes; the passphrase is read from `<path>` (a FIFO is preferred) |
| `--consensus.signing-share` | `0x`-prefixed hex of the commonware encoding of `commonware_cryptography::bls12381::primitives::group::Share` (index and scalar) |
| network identity override | `--consensus.network-identity <0x-hex 96-byte G2>` with `--consensus.network-identity-from-epoch <u64>`; the built-in files `mainnet-network-identity.json` / `testnet-network-identity.json` are `{"from_epoch": u64, "identity": "0x" + 192 hex}` |

A configured share is used only if it matches the public polynomial of the latest finalized boundary outcome at the share's index (6.4).

Reference implementation: crates/consensus-config/src/lib.rs, crates/consensus/src/args.rs, crates/chainspec/src/network_identity.rs.

## 11. Constants

| Constant | Value |
|---|---|
| Consensus p2p namespace | `0x05 \|\| "TEMPO_P2P"` (`union_unique(b"TEMPO", b"_P2P")`) |
| Scheme namespace | `b"TEMPO"` (07-consensus.md) |
| Channel ids | votes 0, certificates 1, simplex resolver 2, broadcast 3, marshal 4, DKG 5 |
| Channel quotas (per peer) | 128/s (0, 1, 2, 5), 8/s (3), 8/s default (4) |
| `max_message_size` default | 8,388,608 bytes |
| Peer-set refresh interval | 30 s |
| Tracked peer sets | 1 |
| Block broadcast deque | 10 per peer |
| Marshal resolver timeout / retry | 2 s / 100 ms |
| Prunable section size | 4,096 blocks |
| `MINIMAL_PEER_SYNC_FINALIZED_BLOCKS` | 64,800 (= 3 × 21,600) |
| `tempo/1` | name `"tempo"`, version 1, 1 message, `NewFinalization = 0x00`, max frame 1,024 bytes |
| `tempo/1` limits | 8 frames/s per connection, 32 verifications/s, 256-frame queue, 2 connections per peer |
| Follower resolver backoff | 250 ms doubling to 30 s |
| FCU heartbeat | 5 min |
| Validator startup backfill FCU batch | 8 blocks |

## 12. Open conflicts

> **Open conflict C-P2P-01**: TIP-1017 says each validator's ed25519 key is "used for signing all consensus p2p messages"; the code signs Simplex votes and certificates with BLS12-381 threshold signatures and uses ed25519 only to authenticate the transport and to sign DKG artifacts. See [conflicts](conflicts.md#c-p2p-01).

> **Open conflict C-P2P-02**: docs protocol/rpc/index.mdx says `consensus_subscribe` emits notarized, finalized and nullified events and `consensus_getLatest` returns the latest notarized block; the code emits only finalized events and always returns `notarized: null`. See [conflicts](conflicts.md#c-p2p-02).

Section 2.1 states the code's behaviour for C-P2P-01 and section 7.2 for C-P2P-02. Neither affects block validity.
