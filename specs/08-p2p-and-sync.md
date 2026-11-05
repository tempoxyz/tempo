# 08 — P2P and sync

This chapter specifies how Tempo nodes talk to each other and how a node obtains, authenticates, persists and serves finalized history. It covers:

- the validator consensus network (the authenticated lookup network of [p2p.md §6](commonware/p2p.md#6-authenticated-lookup-network)), its peer sets and its six channels;
- the execution-layer devp2p network, including the Tempo `tempo/1` RLPx subprotocol that gossips finalization certificates;
- block and certificate backfill, retention, syncing from genesis and consensus snapshots;
- follower mode (certificate and block sources, verification, identity installation, execution-layer forkchoice driving);
- persistence and crash-safety requirements;
- key and share file formats (informative).

The consensus protocol itself (Simplex, the threshold scheme, certificate formats and verification, epochs, the DKG and the on-chain DKG artifacts, the network-identity trust root) is specified in 07-consensus.md. This chapter references those definitions by name and does not restate them. The commonware protocols that the consensus network uses are specified in [commonware/p2p.md](commonware/p2p.md) (transport, handshake, multiplexer, resolver and broadcast), [commonware/simplex.md](commonware/simplex.md), [commonware/dkg.md](commonware/dkg.md), [commonware/cryptography.md](commonware/cryptography.md) and [commonware/codec.md](commonware/codec.md).

Nothing in this chapter is fork-gated within T0..T13: every rule below applies to every mainnet block height. (Fork-gated consensus behaviour such as the T12 leader elector lives in 07-consensus.md.) Where a rule depends on the fork schedule it is stated explicitly using the fork predicate of 01-chain-and-forks.md.

## 0. Conventions and pinned dependencies

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in RFC 2119.

External wire formats that this chapter references rather than restates are pinned as follows:

| Dependency | Pin | Used for |
|---|---|---|
| reth | git rev `966010c905449163ef161530a5ee95ac1e0c8487` | devp2p (discv4, RLPx, `eth` wire), engine API semantics |
| Ethereum | execution-specs Osaka, devp2p specs (RLPx, `eth`), EIP-2124 | devp2p |

Codec notation ([codec.md §2](commonware/codec.md#2-notation)): `varint(x)` is the unsigned LEB128 encoding of an unsigned integer with the canonical-form rules of [codec.md §3](commonware/codec.md#3-varint); `u8`, `u64be` are fixed-width big-endian integers ([§4](commonware/codec.md#4-fixed-width-integers)); `bytes(x)` is `varint(len(x)) || x` ([§5.4](commonware/codec.md#54-length-prefixed-sequences-and-bytes)); a tuple `(A, B)` encodes as `enc(A) || enc(B)`; an `Option<T>` encodes as a `bool` byte (`0x00`/`0x01`) followed by `T` when present ([§5.2](commonware/codec.md#52-option)).

Terms:

- **CL** / **EL**: the consensus layer and the execution layer of a node. In the reference implementation both run in one process; the EL is reth.
- **Validator**: a node running the consensus engine with an ed25519 signing key (`--consensus.signing-key`). It may or may not hold a BLS share in a given epoch (signer vs verifier, 07-consensus.md).
- **Follower**: a node that does not vote. It obtains finalization certificates and blocks from other nodes, verifies them and drives its EL (`tempo node --follow`).
- **Marshal**: the component that orders finalized blocks, persists finalizations and blocks, and repairs gaps (5.1); its consensus-facing wrapper is [simplex.md §10](commonware/simplex.md#10-marshal-inline-wrapper).
- **Finalization**: the Simplex finalization certificate of [simplex.md §3.7](commonware/simplex.md#37-certificates) under the threshold VRF scheme ([cryptography.md §6.2](commonware/cryptography.md#62-certificate-signature-pair)), whose digest is the 32-byte block hash (07-consensus.md §7 "Certificates and follower verification").
- **Block (consensus encoding)**: the RLP encoding of the Tempo execution block (header + body) as specified in 02-encoding.md, with no additional framing. Decoding MUST reject a block whose body does not match the header commitments (transactions root, ommers hash, withdrawals root) and a block whose header carries a block-access-list hash.
- **epoch(h)**, **last(E)**, **first(E)**: the fixed epoch mapping of 07-consensus.md with `epochLength = 21600` on mainnet (chain id 4217) and Moderato (chain id 42431). The boundary block of epoch `E` is `last(E)`; its `extra_data` is the `OnchainDkgOutcome` for epoch `E+1`. The genesis block (height 0) plays the role of the boundary of "epoch −1": its `extra_data` is the outcome for epoch 0.
- **boundary_for(E)**: `0` if `E = 0`, else `last(E−1)`. The outcome in `header(boundary_for(E)).extra_data` describes epoch `E`.

## 1. Overview

A Tempo node has two independent network stacks:

| Stack | Who | Identity | Transport | Purpose |
|---|---|---|---|---|
| Consensus p2p | validators only | ed25519 consensus key (the `publicKey` registered in ValidatorConfigV2) | lookup network over TCP ([p2p.md §6](commonware/p2p.md#6-authenticated-lookup-network)), encrypted stream ([p2p.md §4](commonware/p2p.md#4-encrypted-stream-handshake), [§5](commonware/p2p.md#5-encrypted-transport)) | votes, certificates, block broadcast, backfill, DKG |
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

A validator's consensus identity is its ed25519 key pair ([cryptography.md §3.1](commonware/cryptography.md#31-ed25519-encodings); 32-byte public key). The public key MUST equal the `publicKey` (bytes32) of the validator's ValidatorConfigV2 entry (precompiles/validator-config-and-zones.md). The same key authenticates the p2p handshake, is the participant identifier in Simplex and the DKG (players and dealers are ordered sets of these keys), and signs DKG dealer logs (07-consensus.md). Simplex votes and certificates are *not* signed with ed25519; they carry BLS12-381 threshold partials or recovered signatures (07-consensus.md).

> **Resolved conflict C-P2P-01**: TIP-1017 says the ed25519 key is used for signing all consensus p2p messages; the code uses it only for transport authentication and DKG artifacts, while votes and certificates carry BLS threshold signatures. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-p2p-01).

### 2.2 Transport and handshake

Validators MUST implement the authenticated lookup network of [p2p.md §6](commonware/p2p.md#6-authenticated-lookup-network) with the following parameters (named as in [p2p.md §11](commonware/p2p.md#11-constants)). "Normative" parameters MUST be used for interoperability or because peers depend on them; "default" values are the reference implementation's operator defaults and MAY differ.

| Parameter | Value | Kind |
|---|---|---|
| `namespace` | `union_unique(b"TEMPO", b"_P2P")` = `0x05 \|\| "TEMPO" \|\| "_P2P"` = bytes `05 54 45 4d 50 4f 5f 50 32 50` | normative |
| stream namespace (derived from `namespace`) | `namespace \|\| b"_STREAM"` | normative ([p2p.md §4.1](commonware/p2p.md#41-roles-identities-and-namespace)) |
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

The framing, handshake, key exchange and encryption are specified in [p2p.md](commonware/p2p.md): framing [§2](commonware/p2p.md#2-framing), transcript [§3](commonware/p2p.md#3-transcript), handshake [§4](commonware/p2p.md#4-encrypted-stream-handshake), encrypted transport [§5](commonware/p2p.md#5-encrypted-transport). A connection is authenticated to an ed25519 public key; the application sees every inbound message tagged with that key.

On the authenticated stream, each encrypted frame carries one network message ([p2p.md §6.1](commonware/p2p.md#61-network-messages)):

```
Message := 0x00 || Data          ; application data
         | 0x01                  ; Ping
Data    := varint(channel) || bytes(payload)
```

`channel` is the channel id of section 3 (a u64). `payload` is the channel's application message. Pings are transport keep-alives. A message on an unknown channel, or one that does not decode, closes the connection ([p2p.md §6.3](commonware/p2p.md#63-receiving)).

### 2.3 Peer addresses and admission

Each peer in a tracked set has an asymmetric address `{ingress, egress}` ([p2p.md §6.5.2](commonware/p2p.md#652-addresses)) built from its ValidatorConfigV2 entry:

- `ingress` = `Ingress::Socket(parse_socket_addr(entry.ingress))` — the address other validators dial. `entry.ingress` is a string `"<ip>:<port>"` (IPv6 as `"[<ip>]:<port>"`) a literal IPv4 or IPv6 socket address (no host names, no IPv6 zone index).
- `egress` = `(parse_ip_addr(entry.egress), port 0)` — only the IP is used: it is the source address the peer's outbound connections come from.

An entry whose `publicKey` is not a valid ed25519 point encoding ([cryptography.md §3.2](commonware/cryptography.md#32-public-key-decoding)), or whose `ingress` or `egress` fails to parse, is *undecodable* (2.4 says how undecodable entries are handled).

Admission rules of the lookup network (connection slots [p2p.md §6.5.3](commonware/p2p.md#653-connection-slots), accepting [§6.5.4](commonware/p2p.md#654-accepting-connections), dialing [§6.5.5](commonware/p2p.md#655-dialing)):

1. Outbound dials go only to **primary** peers, at their ingress address.
2. Inbound connections are accepted only from identities in the union of the primary and secondary peers of the tracked set(s).
3. Unless `bypass_ip_check` is set, an inbound connection whose source IP is not one of the registered egress IPs (of any primary or secondary peer) is rejected before the handshake.
4. Unless `allow_private_ips` is set, connections from or to non-global IP addresses are rejected.
5. Messages sent to all peers (`All`, [p2p.md §6.2](commonware/p2p.md#62-sending)) go to every connected primary and secondary peer.

### 2.4 Peer-set derivation

Peer sets are derived only from finalized state. The node keeps the highest finalized tip that consensus (marshal) has reported, `consensus_tip`, initialised from the finalization archive tip at startup (5.1.5).

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

- If nothing was tracked before, or the key sets of `primary` or `secondary` differ from the last tracked set, the node MUST track a new peer set with index `h` and these primary and secondary peers (`track`, [p2p.md §6.5.1](commonware/p2p.md#651-peer-sets)). With `tracked_peer_sets = 1` the previous set is dropped, disconnecting peers that left the union.
- If only addresses changed, the node MUST overwrite the addresses of the existing set in place (`overwrite`, [p2p.md §6.5.1](commonware/p2p.md#651-peer-sets)).
- In all cases the remembered height becomes `h`.

When peer sets are refreshed:

1. Once at engine construction, from EL state alone, **before** marshal, the executor or the DKG manager start (the DKG manager may need peers to recover and authenticate the tip). If this initial read fails (missing header or state), startup MUST fail.
2. On every marshal `FinalizedBlock` update (the block is acknowledged immediately) and `FinalizedTip` update (5.1.3), after raising `consensus_tip` to the reported height if higher.
3. Every 30 s when no update arrived (the timer restarts on each update). Errors on these later refreshes are ignored; the previous set stays in force.

Consequences that implementers MUST preserve:

- Peer membership follows the DKG outcome of the latest finalized boundary (current players are always dialed) plus the contract's active set at the finalized tip (joining validators are reachable before they become players).
- Addresses always come from ValidatorConfigV2 at the finalized tip, including for players that are no longer active.
- A node whose EL is behind its consensus tip derives peers from the EL's finalized height. A node whose EL is ahead derives them from the consensus tip.

> **Note**: ValidatorConfigV2 has no entries before it is populated after T2 (mainnet genesis allocates only the V1 contract at `0xCCCCCCCC00000000000000000000000000000000`). The invariant assertions above therefore fail for heights before ValidatorConfigV2 holds entries for every player of the latest boundary outcome, so a validator cannot start its consensus engine from such a height; see 5.7.

> **TODO**: the lowest mainnet height at which ValidatorConfigV2 held a decodable entry for every player of the latest boundary outcome (the lowest height from which a validator-mode node can start) was not determined from the code; it depends on when the T2 migration populated the contract on mainnet.

### 2.5 Misbehaviour and blocking

Components that detect Byzantine behaviour from an authenticated peer (an invalid certificate or signature, an undecodable message on a channel, a resolver response that fails verification) block the peer ([p2p.md §6.7](commonware/p2p.md#67-blocking)): the connection is dropped and the peer is refused for `block_duration` (4 h by default). A node MUST NOT block a peer for a certificate it cannot verify only because it lacks the epoch's scheme; in particular schemes MUST be retained for the two most recent epochs after an epoch ends (07-consensus.md), because straggling peers keep re-proposing and certifying the outgoing epoch's boundary block.

## 3. Consensus channels

### 3.1 Channel map

| Id | Name | Per-peer quota (inbound and outbound, each direction independently) | Epoch-multiplexed | Payload |
|---|---|---|---|---|
| 0 | votes | 128 msg/s | yes | `Vote` ([simplex.md §3.6](commonware/simplex.md#36-votes)) |
| 1 | certificates | 128 msg/s | yes | `Certificate` ([simplex.md §3.7](commonware/simplex.md#37-certificates)) |
| 2 | simplex resolver | 128 msg/s | yes | resolver message ([p2p.md §9.1](commonware/p2p.md#91-message)) with key `u64be(view)` (3.3.3) |
| 3 | block broadcast | 8 msg/s | no | consensus block encoding (3.3.4) |
| 4 | marshal backfill | `--consensus.backfill-frequency` msg/s, default 8 | no | resolver message ([p2p.md §9.1](commonware/p2p.md#91-message)) with the marshal key of 3.3.5 |
| 5 | DKG | 128 msg/s | yes | Tempo DKG message (3.3.6) |

Votes and certificates are signed with the threshold VRF scheme ([cryptography.md §6](commonware/cryptography.md#6-threshold-vrf-scheme)). Quotas are GCRA quotas of `n` messages per second with burst `n` ([p2p.md §7](commonware/p2p.md#7-rate-limiting)), enforced per channel and per peer. An inbound message over quota is delayed, not dropped: the receiver stops reading that connection until the quota allows the message ([p2p.md §6.3](commonware/p2p.md#63-receiving), [§7.2](commonware/p2p.md#72-channel-quotas)), which stalls every channel of the connection. Outbound, recipients over quota are left out, and a send is refused only when every recipient is over quota. Quotas are local policy, but a node that sends above its peers' quotas slows its own connections to them; a conforming node SHOULD NOT exceed them.

### 3.2 Epoch multiplexing

Channels 0, 1, 2 and 5 are multiplexed by epoch with the multiplexer of [p2p.md §8](commonware/p2p.md#8-epoch-multiplexer) (all subchannels share the channel's quota): the channel payload is

```
MuxedPayload := varint(epoch) || inner_message
```

A node registers subchannel `E` on channels 0, 1 and 2 when it enters epoch `E` (starts the Simplex instance for `E`), and on channel 5 when its DKG manager runs the ceremony of epoch `E`. Registration is local and is not signalled to peers ([p2p.md §8](commonware/p2p.md#8-epoch-multiplexer)).

Each registered subchannel has a receive queue of `--consensus.mailbox-size` messages (default 16,384). The multiplexer reads the channel's messages in arrival order and never waits on a consumer: a message whose subchannel queue is full is dropped, and a payload whose epoch prefix is not a canonical `varint` is dropped. Messages for a subchannel that is not registered are dropped, except on channel 0 (votes).

On channel 0 the multiplexer has a **backup queue**. A vote message for an unregistered epoch is pushed to it as `(their_epoch, sender, inner_message)`, without decoding `inner_message`. The backup queue holds `--consensus.mailbox-size` entries and keeps arrival order; an entry that does not fit is dropped. Its only consumer is the component that enters and exits epochs (the epoch manager). It takes entries one at a time, in queue order, interleaved with its own epoch transitions, and handles each with:

```python
def on_vote_for_unregistered_epoch(their_epoch, sender):   # inner_message is discarded unread
    if no epoch has been entered yet:
        return
    reference = latest entered epoch
    if their_epoch <= reference:
        return                                  # a straggler in an epoch we left, or ours
    # A peer votes in a later epoch: the boundary of our epoch must be finalized.
    marshal.hint_finalized(height=last(reference), targets=[sender])
```

The vote itself is never verified: a hint only starts a targeted fetch (5.1.8), and the response must verify under the node's own scheme for `reference` (3.3.5). A peer that answers with an invalid finalization is blocked (2.5). A hint is a no-op once the finalization of `last(reference)` is stored or that height is processed. While a fetch for it is in progress, each further hint adds its sender to the fetch's targets. Dropped backup entries lose nothing, because every later vote from an epoch ahead triggers the same hint.

The hint makes marshal fetch the finalization of `last(reference)` (with its block) from the sender (3.3.5). Once the DKG manager processes that finalized boundary block it enters the next epoch; this repeats one epoch at a time until the node reaches the network's epoch (5.6).

When a node exits epoch `E` (at the first finalized block of epoch `E+1`, 07-consensus.md) it deregisters `E`'s subchannels and deletes the scheme of epoch `E−2`.

### 3.3 Channel payloads

All payloads are encoded with the codec of [codec.md](commonware/codec.md), decoded under its rules (no trailing bytes, [§11](commonware/codec.md#11-decoding-rules)), and carried in `Data` messages ([p2p.md §6.1](commonware/p2p.md#61-network-messages)).

#### 3.3.1 Channel 0: votes

`Vote` (notarize, nullify, finalize) of [simplex.md §3.6](commonware/simplex.md#36-votes), under the mux prefix. Signing domains and verification: 07-consensus.md and [simplex.md §4](commonware/simplex.md#4-signing).

#### 3.3.2 Channel 1: certificates

`Certificate` (notarization, nullification, finalization) of [simplex.md §3.7](commonware/simplex.md#37-certificates) under the mux prefix. Informative summary (normative layout: 07-consensus.md §7): a finalization's encoding is `Proposal || vrf::Certificate` where `Proposal = varint(epoch) || varint(view) || varint(parent_view) || digest[32]` and `vrf::Certificate = vote_signature[48] || seed_signature[48]` (compressed G1 points), as in the golden frame of 4.3.4.

#### 3.3.3 Channel 2: simplex resolver

The Simplex resolver fetches certificates for views a node missed ([simplex.md §8.14](commonware/simplex.md#814-fetching-missing-certificates-resolver)). The wire message and the requester and responder rules are those of [p2p.md §9](commonware/p2p.md#9-resolver-protocol):

```
Message := u64be(id) || Payload
Payload := 0x00 || Key            ; Request
         | 0x01 || bytes(value)   ; Response (same id as the request)
         | 0x02                   ; Error
```

For channel 2, `Key = u64be(view)` (8-byte big-endian view number) and a response value is the encoding of a `Certificate`: a nullification of exactly that view, or a notarization or finalization of that view or a later one. Timeouts: requests are retried after `--consensus.wait-for-peer-response` (default 2 s).

#### 3.3.4 Channel 3: block broadcast

Channel 3 carries the buffered broadcast engine ([p2p.md §10](commonware/p2p.md#10-buffered-broadcast)). Each message is exactly one consensus block encoding (the raw block RLP), not epoch-multiplexed and not otherwise framed. The leader broadcasts its proposed block to all peers (sent with priority). Receivers decode it (rejecting body/header mismatches and BAL hashes, section 0) and hand it to marshal and to the application for verification. A block from a primary peer of the latest peer set is also cached, keyed by its digest (at most `--consensus.deque-size` = 10 digests per peer); a block from any other peer satisfies local waiters but is not cached. A block received on channel 3 has no authority by itself; it becomes final only through a finalization (07-consensus.md).

#### 3.3.5 Channel 4: marshal backfill

Channel 4 carries the marshal resolver, an instance of the resolver protocol of [p2p.md §9](commonware/p2p.md#9-resolver-protocol), with the wire message of 3.3.3 and the key:

```
Key := 0x00 || digest[32]                       ; Block: a block by hash
     | 0x01 || varint(height)                   ; Finalized: the finalization at a height, with its block
     | 0x02 || varint(epoch) || varint(view)    ; Notarized: the notarization of a round, with its block
```

Response values:

| Request | Response value | Requester MUST check |
|---|---|---|
| `Block(d)` | block encoding | decodes; `keccak256(rlp(header)) == d` |
| `Finalized{h}` | `enc(Finalization) \|\| enc(Block)` | the finalization's epoch is `epoch(h)` and it verifies under that epoch's scheme (07-consensus.md); its payload equals the block hash; the block's number is `h` |
| `Notarized{r}` | `enc(Notarization) \|\| enc(Block)` | the notarization's round is `r` and it verifies under the scheme of `r.epoch`; its payload equals the block hash |

A response that fails these checks SHOULD cause the requester to block the responder (2.5) and retry with another peer. A `Finalized` or `Notarized` response for an epoch whose scheme the requester no longer (or does not yet) holds is dropped without blame. How marshal uses the responses is in 5.1 and 5.3. Resolver parameters (reference): request timeout 2 s, retry delay 100 ms, requests and responses not sent with priority, peers chosen from the primary peers of the latest tracked peer set ([p2p.md §9.2](commonware/p2p.md#92-requester)).

#### 3.3.6 Channel 5: DKG

Under the mux prefix (subchannel = the ceremony's epoch):

```
DkgMessage := 0x00 || DealerPubMsg || DealerPrivMsg   ; dealer -> one player
            | 0x01 || PlayerAck                    ; player -> its dealer
```

The message types and the envelope are those of [dkg.md §5](commonware/dkg.md#5-messages) and [§5.4](commonware/dkg.md#54-tempo-dkg-channel-envelope). Every DKG message is sent to exactly one recipient, with priority. Semantics, validity and when to send: 07-consensus.md §9.3 "DKG messages".

### 3.4 Message size limits

- A node MUST NOT send an application payload (including the mux prefix) larger than its configured `max_message_size` (default 8,388,608 bytes). The reference implementation drops such an outbound message and counts it, instead of passing it to the transport.
- Inbound encrypted frames whose payload exceeds the receiver's `max_message_size` plus the 32 bytes of message framing and authentication tag are rejected by the transport ([p2p.md §5.3](commonware/p2p.md#53-encrypted-frames)).
- A proposed block travels as a single channel-3 message and inside channel-4 responses. Every node MUST accept inbound application payloads of at least 8,388,608 bytes (the block RLP size limit `MAX_RLP_BLOCK_SIZE` of EIP-7934, 05-block-execution.md). With the reference default (`max_message_size = 8,388,608`) a channel-4 response carrying a block whose RLP is within a few hundred bytes of that limit exceeds the limit once the finalization and `Message` framing are added, and is dropped by the responder; such a block can still be obtained from the EL (devp2p) or after a retry from a peer configured with a larger limit. Operators SHOULD NOT lower the default.

## 4. Execution-layer devp2p

### 4.1 Stack

Every Tempo node (validator or follower) runs reth's devp2p stack at the pinned revision:

- **Discovery**: discv4 (reth default). Mainnet and Moderato bootnodes are built into the node's chain configuration.
- **Transport**: RLPx with the `p2p` hello handshake. The node advertises `eth/66` through `eth/71` (every version reth supports at the pinned revision) and, when enabled, `tempo/1` (4.3).
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

There is no RLP wrapping: `enc(Finalization)` is the encoding of a `Finalization` ([simplex.md §3.7](commonware/simplex.md#37-certificates), codec of [codec.md](commonware/codec.md)) (3.3.2). Decoding rules, in order:

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

## 5. Marshal, backfill and sync

### 5.1 Marshal

Marshal turns consensus activity into a gap-free, height-ordered stream of finalized blocks. Every validator and every follower runs one marshal. It persists finalizations and finalized blocks, keeps a cache of recent notarized and verified blocks, repairs gaps from peers (5.3) and answers peers' backfill requests (5.4). Simplex reaches it through the Inline wrapper of [simplex.md §10](commonware/simplex.md#10-marshal-inline-wrapper); the rest of the node consumes its output updates (5.1.3).

The names below are this specification's. Only the backfill wire format (3.3.5) is interoperable; everything else in this section is local behaviour that other nodes rely on only through what a node serves and when it votes.

#### 5.1.1 State and stores

Marshal keeps:

- `processed_height`: the highest height whose finalized block every consumer acknowledged, or none. It is durable.
- `round_floor`: a round at or below which no certificate-bound work is needed. It is derived at startup (5.1.5) and advances with `processed_height` (5.1.6).
- `tip`: the highest height reported in a `FinalizedTip` during this run.
- `pending_floor`: a floor finalization whose block has not arrived yet, or none (5.1.7).
- `in_flight`: the blocks dispatched to consumers and not yet acknowledged, in height order, at most `max_pending_acks` of them.

It uses these logical stores (their on-disk layout is implementation-defined, 9.1):

| Store | Contents | Indexed by |
|---|---|---|
| finalization archive | one `Finalization` per height, insert-only | height, block digest |
| finalized-block store | finalized blocks (5.2) | height, block digest |
| delivery metadata | `processed_height` | — |
| consensus cache, one per epoch | verified blocks (several per view allowed), notarized blocks, notarizations and finalizations by view; certified blocks by height; plus the range of epochs that may have a cache | view or height, block digest |

Marshal does not own the block broadcast buffer of 3.3.4, but reads it. `find(d)` looks for the block with digest `d` in the broadcast buffer, then in the consensus caches (newest epoch first; verified, notarized, then certified blocks), then in the finalized-block store.

A finalized block is *stored* with:

```python
def store_finalized(h, B, f):                 # f is None when B is finalized only through a descendant
    if h <= (processed_height or 0):
        return False                           # already delivered; ignored
    finalized_blocks.put(B)                    # buffered: readable at once, durable after the next sync
    if f is not None:
        finalizations.put(h, digest(B), f)
    barrier = min(barrier, h)                  # dispatch stops at h until a sync covers this write
    if f is not None and h > tip:
        emit FinalizedTip(f.round, h, digest(B))
        tip = h
    return True
```

Every step that stores finalized blocks ends by starting a durable sync of both stores. When the sync completes, `barrier` is cleared for the writes it covers and dispatch resumes (5.1.4). A sync failure is fatal.

#### 5.1.2 Inputs

| Input | Source | Effect |
|---|---|---|
| `notarization(n)` | Simplex (validators) | Write `n` to the cache at its round. Its sync runs in the background. If `find(n.payload)` returns a block that the verified cache does not already hold at that round, write it as a notarized block too. A notarization alone never triggers a fetch. |
| `finalization(f)` | Simplex (validators); the follower driver (7.4) | Write `f` to the cache at its round and wait until it is durable. If `find(f.payload)` returns `B`: `store_finalized(h(B), B, f)`, advance the round floor if `h(B) ≤ processed_height` (5.1.6), run repair (5.3) and start a sync. Otherwise request `Block(f.payload)` (3.3.5) for the finalized chain. |
| `proposed(round, B)` | the Inline wrapper's `broadcast` | Send `B` to all peers on channel 3 (3.3.4), then store it as verified for `round`. Sending first keeps propagation off the storage path. |
| `store_verified(round, B)` | the Inline wrapper's `verify` | Write `B` to the verified cache at `round`, unless that view already holds this digest. Returns once the write is durable. Presence in the verified cache is not a validity claim. |
| `store_certified(round, B)` | the Inline wrapper's `certify`; the follower driver for upstream blocks (7.4) | Write `B` to the notarized cache at `round`, unless the verified cache already holds it there. Returns once the block and the round's notarization (if one was written earlier) are durable. |
| `hint_finalized(h, targets)` | epoch catch-up (3.2, 5.6); the follower driver (7.5) | 5.1.8 |
| `set_floor(f)` | the follower executor (7.6) | 5.1.7 |
| backfill responses | resolver (3.3.5, 7.3) | 5.3 |

Every block that marshal receives or writes, by any of these paths, also wakes local waiters for its digest (5.1.9). If its digest is the payload of `pending_floor`, the floor is applied (5.1.7) and the block is not processed further.

#### 5.1.3 Outputs

Marshal emits two kinds of update. Each update goes to every consumer, in a fixed order. Validators' consumers are the application, the executor (8), the DKG manager, the peer manager (2.4), the RPC feed and `tempo/1` gossip (4.3.3). Followers' consumers are the executor (7.6), the driver (7.5), the RPC feed and gossip, with the driver ahead of gossip.

`FinalizedTip(round, height, digest)` reports a new finalized tip:

- It is emitted when `store_finalized` writes a finalization above every tip reported in this run, and once at startup for the finalization archive's highest entry (5.1.5).
- Within one run, tip heights strictly increase. The startup tip can repeat a height reported before the restart.
- The finalization is readable from the finalization archive when the tip is emitted. The tip is not a durability signal: the write may not be durable yet.
- The tip can name a height whose ancestors marshal does not hold yet.
- A finalization whose block marshal does not hold yields no tip, because its height is unknown. The tip follows once the block arrives.
- When a tip for height `h` is emitted, it precedes `FinalizedBlock` for `h` in the same run. A height finalized only through a descendant gets a block update and no tip.

`FinalizedBlock(block, ack)` delivers one finalized block:

- Heights are delivered in strictly increasing order without gaps, starting at `processed_height + 1`, or at 0 (the genesis block) when nothing was processed.
- A block is emitted only after it, and its finalization if marshal has one, are durable.
- Delivery is at least once. A block can be delivered again after a restart (5.1.5) or after a floor is applied (5.1.7). Consumers MUST tolerate a repeated block and still acknowledge it.
- At most `max_pending_acks` blocks are unacknowledged at a time. Reference values are 1 for followers and, for validators, the number of unpersisted blocks the EL holds in memory before it stops processing engine requests. Validators acknowledge only after EL persistence (8), so their window must exceed the EL's persistence batch.

Each consumer gets its own copy of `ack` and MUST acknowledge it once it has processed the block. A consumer that does not need the block for durable state, such as gossip or the peer manager, acknowledges at once. The block counts as acknowledged only when every copy is acknowledged. A copy dropped without acknowledging stops marshal, which is fatal to the node.

#### 5.1.4 Delivery

```python
def next_height():
    return 0 if processed_height is None else processed_height + 1

def dispatch():
    if pending_floor is not None:
        return
    while len(in_flight) < max_pending_acks:
        h = in_flight[-1].height + 1 if in_flight else next_height()
        if barrier is not None and h >= barrier:
            return                              # the block at h may not be durable yet
        B = finalized_blocks.get(h)
        if B is None:
            return                              # a gap; repair (5.3) fills it
        ack = new_ack()
        emit FinalizedBlock(B, ack)
        in_flight.append((h, digest(B), ack))

def on_acknowledged():                          # runs when in_flight[0] is fully acknowledged
    while in_flight and in_flight[0].ack is acknowledged:
        h, d, _ = in_flight.popleft()
        processed_height = h
        cancel resolver requests for heights <= h
        f = finalizations.get(h)
        if f is not None:
            advance_round_floor(h, f.round)     # 5.1.6
    persist processed_height                    # durable sync, before any further dispatch
    dispatch()
```

Acknowledgements are consumed in height order, so `processed_height` never skips a block that is still in flight. Because blocks are dispatched only once durable and `processed_height` is persisted only after acknowledgement, a crash never leaves `processed_height` above a block the stores lack.

#### 5.1.5 Startup and restart

On startup (both modes), before any consumer runs:

1. Open the stores and run the startup checks of 9.4.
2. Choose the startup anchor. If the finalization archive is empty, the anchor is the genesis block, which MUST equal the EL's genesis; marshal stores it at height 0 unless it is present or `processed_height` is above 0. Otherwise the anchor is the archive's lowest finalization (the floor of 6.4, already verified there).
3. Restore `processed_height`. Derive `round_floor` as the round of the highest stored finalization at or below `processed_height` (or the zero round). Raise it to the round of the finalization at `processed_height + 1` if that finalization and its block are both stored.
4. Emit `FinalizedTip` for the finalization archive's highest entry, if any.
5. Open the consensus caches of every epoch in the recorded range.
6. Install a non-genesis anchor as a floor (5.1.7). It has no effect when its round is at or below `round_floor`.
7. Run repair (5.3), sync, and dispatch (5.1.4).

So every block above the persisted `processed_height` is delivered again after a restart. A restored node with no `processed_height` gets the anchor's block first. The *startup floor* is `max(processed_height, anchor height)`. The validator executor replays EL history up to it before marshal's deliveries matter (5.7).

#### 5.1.6 Round floor and cache retention

```python
def advance_round_floor(h, r):
    if h > (processed_height or 0) or r <= round_floor:
        return
    old = round_floor
    round_floor = r
    # Retain a window behind the previous floor.
    delete the consensus caches of every epoch < old.epoch
    in old.epoch's cache, delete views < old.view - view_retention
    cancel resolver requests bound to rounds <= r
    if pending_floor is not None and pending_floor.round <= r:
        pending_floor = None                    # its block is already processed; resume
        repair(); dispatch()
```

Deletion is in whole sections of 4,096 views, so a cache can keep more than `view_retention` views. `view_retention` is 10 × `--consensus.views-to-track` (2,560 views by default) on validators, so they can serve `Notarized{r}` requests (5.4), and 1 on followers. Certified blocks above `processed_height` are cached by height when an ancestry walk fetches them (5.1.9). They are deleted with their epoch's cache and below an applied floor.

#### 5.1.7 Floors

A *floor* moves the start of delivery to a finalized block. The startup anchor (5.1.5) and `set_floor(f)` both install one:

```python
def install_floor(f, from_set_floor):
    if f.round <= round_floor:
        return                                  # stale floor; ignored
    require f verifies under the scheme of f.epoch   # failure is fatal: a local caller supplied f
    write f to the cache at f.round
    if from_set_floor and pending_floor is not None and pending_floor.round >= f.round:
        return                                  # keep waiting for the newer pending floor
    pending_floor = f
    B = find(f.payload)
    if B is not None:
        apply_floor(B)
    else:
        drop in_flight                          # their acknowledgements are ignored
        request Block(f.payload) for the finalized chain

def apply_floor(B):                             # B is the block named by pending_floor
    f = pending_floor
    pending_floor = None
    h = h(B)
    if h <= (processed_height or 0):
        advance_round_floor(h, f.round)
        repair(); dispatch()
        return
    finalized_blocks.put(B); finalizations.put(h, digest(B), f); durable sync
    if h > tip:
        emit FinalizedTip(f.round, h, digest(B)); tip = h
    processed_height = h - 1                    # so that B itself is delivered next
    advance_round_floor(h - 1, f.round)
    persist processed_height
    drop in_flight
    prune the finalization archive, the finalized-block store and the certified-block caches below h
    repair(); dispatch()
```

While `pending_floor` is set, repair and dispatch pause. In Tempo the finalization archive and the finalized-block store ignore pruning (5.2), so a floor only moves the delivery start and prunes certified-block caches.

#### 5.1.8 Hints

`hint_finalized(h, targets)` asks for the finalization at height `h`:

```python
def hint_finalized(h, targets):
    if finalizations.has(h):
        return
    if h <= (processed_height or 0):
        return
    resolver.fetch_targeted(Finalized{h}, targets)   # a fetch already in progress gains these targets
```

The response is checked per 3.3.5. If no scheme is known for `epoch(h)` when it arrives, it is dropped as stale without penalizing the peer, and the hint has no effect. A valid response is stored with `store_finalized(h, B, f)`, which reports a new tip if `h` is above it, and repair then walks down from `B` (5.3). Hints are fire-and-forget: nothing is reported back to the caller. Followers ignore `targets` and ask the upstream (7.3).

#### 5.1.9 Lookups

The Inline wrapper ([simplex.md §10](commonware/simplex.md#10-marshal-inline-wrapper)) and the consumers use these operations. None of them waits for durability.

| Operation | Result |
|---|---|
| `has_verified_block(round)` | true iff the verified cache holds a block at `round` |
| `block(d, fetch_round=r)` | `find(d)` if it succeeds. Otherwise the caller waits until a block with digest `d` reaches marshal by any path (5.1.2). If `r` is given and above `round_floor`, marshal also requests `Notarized{r}` (3.3.5). The caller MAY abandon the wait. A block obtained this way may not have been stored yet. |
| `block(d)` with an ancestry height bound `h` | as above, but requests `Block(d)`; a matching response at height ≤ `h` and above `processed_height` is cached as a certified block. Used when walking the ancestry of a block the node already accepted (building on, verifying or certifying it). |
| `finalized_block(h)`, `finalization(h)` | the finalized-block store or the finalization archive at `h`, or none; never fetches |
| `latest()` | height, digest and round of the finalization archive's highest entry |
| `processed_height()` | `processed_height` |

### 5.2 Storage model

Validators and followers keep the same consensus storage (so a node can switch modes without migration, 9.5):

- **Finalization archive**: maps height → `Finalization`, also looked up by block digest. It holds one finalization per finalized height from the node's floor upward (heights for which only a later descendant's certificate was received may be absent). The genesis block MUST NOT have a finalization. It is never pruned, in either mode.
- **Finalized-block store**: a *hybrid* store. A prunable store (4,096 blocks per section) holds recently finalized blocks; every block at or below the EL's finalized height is served from the EL (canonical blocks only). On every insertion the prunable store drops whole sections below `el_finalized − retention + 1` (default retention 64,800 = 3 × 21,600 blocks, so it holds between 64,800 and 68,895 blocks once the EL has caught up). It never drops a block the EL has not finalized, and marshal's prune requests have no effect on it. An insertion at a height the prunable store has already dropped is a successful no-op, since the EL holds that block. Gap tracking treats every height at or below the EL's finalized height as present.
- **Delivery metadata**: `processed_height` (5.1.1).
- **Consensus caches**: the per-epoch caches of 5.1.1, retained per 5.1.6.

### 5.3 Gap repair

Marshal repairs the finalized chain above `processed_height` (5.1.4 delivers it). Repair runs after every stored finalization, after every batch of resolver deliveries, after a floor is applied and at startup. It does nothing while `pending_floor` is set.

```python
def repair():
    start = (processed_height or 0) + 1
    # 1. Finalizations above the last stored block: anchor the highest one first.
    t = finalizations.last_index()
    if t is not None and t >= start and (finalized_blocks.last_index() or -1) < t:
        f = finalizations[t]
        B = find(f.payload)
        if B is not None: store_finalized(t, B, f)
        else: request Block(f.payload) for the finalized chain at height t
    # 2. Internal gaps: walk parent hashes down from the block above each gap.
    for each gap (lo, hi] of missing heights at or above start, lowest first:
        cursor = finalized_blocks.get(hi + 1)
        while h(cursor) - 1 > lo:
            P = find(parent(cursor))
            if P is None:
                request Block(parent(cursor)) for the finalized chain at height h(cursor) - 1
                break out of both loops
            store_finalized(h(cursor) - 1, P, cached finalization for digest(P), if any)
            cursor = P
    # 3. Ask for finalizations of the lowest missing heights.
    request Finalized{h} for up to max_repair missing heights >= start
```

A block fetched by `Block(d)` is authenticated by `d`, which a stored child or a verified finalization committed to. It is stored as finalized when it was requested for the finalized chain or a finalization for it is cached, because a verified finalization of a descendant finalizes all ancestors. A `Finalized{h}` response carries the finalization and block for `h`, verified per 3.3.5.

Requests go over channel 4 (validators) or to the follower resolver (7.3). Marshal handles resolver messages (responses and peers' requests) in batches of up to `max_repair` = 20. It verifies the batch's certificates together, runs repair, starts one sync, and then answers the batch's peer requests. Requests at or below `processed_height` (or bound to a round at or below `round_floor`) are not sent, and are cancelled when the floors pass them.

### 5.4 Serving obligations

A validator MUST answer channel-4 requests it can satisfy:

- `Block(d)` when `find(d)` succeeds: the broadcast buffer, the consensus caches, the prunable store or, for canonical EL blocks, the EL;
- `Finalized{h}` for any height in its finalization archive, with the block from the finalized-block store;
- `Notarized{r}` while its consensus cache still holds the notarization of `r` and the block it names (5.1.6).

It answers `Error` (or nothing) when it cannot. A node whose EL prunes history can serve blocks only within its retention window; requests for heights below it fail without penalty and the requester retries elsewhere. A node under load MAY drop peers' requests before its own responses.

### 5.5 Retention guarantees

| Data | Reference retention | Guarantee a peer can rely on |
|---|---|---|
| Finalized blocks in the prunable store | ≥ 64,800 blocks behind the EL's finalized tip (`MINIMAL_PEER_SYNC_FINALIZED_BLOCKS`, `--consensus.finalized-blocks-retention`) | blocks up to three mainnet epochs behind the finalized tip are servable from consensus storage |
| Finalized blocks older than that | served from the EL; available iff the EL has not pruned them (RPC/archive nodes default to archive mode; `--minimal` prunes) | none |
| Finalizations | the finalization archive is never pruned: a node keeps every finalization it stored from its first stored height (genesis+1 for a node synced from genesis, the snapshot anchor for a restored node) upward; heights finalized only implicitly (through a descendant's certificate during backfill) may lack one | validators that are not freshly restored hold the finalization of every height of the current and previous epoch and of every boundary they processed |
| Notarizations and notarized blocks | at least `view_retention` views behind the processed round (5.1.6) | none |
| DKG events | current and previous epoch | (local only) |

Validators SHOULD keep EL history for at least `MINIMAL_PEER_SYNC_FINALIZED_BLOCKS` blocks so that peers up to three epochs behind can catch up over consensus p2p.

### 5.6 Epoch catch-up (validators)

A validator that is behind enters epochs one at a time:

```python
while behind:
    E = latest entered epoch
    # Triggered by a vote for an epoch > E (3.2).
    marshal.hint_finalized(last(E), targets=[voter])   # fetch Finalized{last(E)} from the voter
    # The finalization of last(E) verifies under epoch E's scheme, which the node has.
    # Marshal backfills epoch E's blocks by parent hash and delivers them in order (5.3).
    # The DKG manager processes the finalized boundary block last(E), persists the
    # state for epoch E+1 (07-consensus.md) and only then enters epoch E+1, which
    # registers the scheme for E+1 and the channel subchannels for E+1.
```

A node MUST NOT install the scheme of epoch `E+1` before the boundary block `last(E)` is finalized and processed, and MUST NOT accept a hint target's claim about any other height: hints always name the boundary of the node's own current epoch.

### 5.7 Syncing from genesis

**Follower mode** syncs any history, including from genesis:

1. At genesis the EL's finalized height is 0, so the follower installs the epoch-0 scheme from the genesis outcome and pins the configured network identity (7.5).
2. It verifies the upstream's latest finalization against the pinned identity (mainnet: `from_epoch = 2042`) and reports it to marshal.
3. Marshal fetches the tip block and walks parent hashes down to height 1 (5.3), storing every block as finalized; blocks are delivered in order and executed by the EL (7.6). Historical certificates are not needed: the verified tip authenticates its whole ancestry by hash.

**Validator mode** derives peers from ValidatorConfigV2 at the finalized tip (2.4) and replays finalized blocks through the engine API with `VALID` required (8). A validator therefore cannot start consensus from a state whose finalized height precedes the population of ValidatorConfigV2 with entries for every player of the latest boundary outcome. To join from scratch, a validator MUST first reach a recent finalized height in follower mode or from a snapshot (section 6), then start in validator mode on the same storage (9.5).

In validator mode, on startup the executor first replays finalized blocks from the EL's finalized height up to the startup floor (5.1.5), reading them from marshal's stores and falling back to the EL. It issues a forkchoice update every 8 delivered blocks and at the startup floor, after waiting until the EL reports ready (a forkchoice update reaffirming the EL's own current forkchoice returns `VALID`, polled every 1 s). If a block in that range cannot be sourced, startup fails.

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

The consensus archive is one file described by `consensus_archive`. It holds two of the logical stores of 9.1, and nothing else:

- the **finalization archive**, with every finalization from the anchor height to the tip height that the source holds;
- the **finalized-block store**'s prunable part, with every block above `execution_finalized_height` that the source holds.

It excludes the DKG state, the follower identity record, Simplex vote journals, the consensus caches and marshal's delivery metadata; a restored node rebuilds them (6.4).

The archive's internal encoding (container, compression, file names and store layout) is implementation-defined. A snapshot is only guaranteed to install on the implementation, and storage format version, that produced it. The reference archive is a zstd-compressed tar of its two store directories. The manifest fields above and the logical contents are the same for every implementation.

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
3. require that every extracted entry is a regular file or directory, that every file is listed in `output_files` with matching size and blake3 hash, and that every listed file is present;
4. require that the extracted files form the two stores of 6.1 in the installer's own storage format, and reject the archive otherwise (for example, the reference installer requires each top-level directory to belong to one of its two stores);

then move the stores into the consensus data directory (default `<datadir>/consensus`), refusing to overwrite existing files unless forced.

These checks only protect integrity against the manifest. Authenticity comes from the startup checks of 6.4.

### 6.4 Trust: verifying a restored snapshot at startup

A node started on restored storage performs, before any actor runs:

1. **Archive consistency** (9.4): the finalization archive's tip certificate epoch equals `epoch(tip_height)`; its first index is not 0; the tip header, where the prunable store or the EL has a block at that height, has number `tip_height` and hash equal to the tip certificate's payload.
2. **Floor verification**: the floor is the first finalization in the archive (the anchor). The node reads `header(boundary_for(cert.epoch))` from the hybrid store, decodes its `OnchainDkgOutcome`, requires `outcome.epoch == cert.epoch`, builds the full verifier scheme from `outcome.players` and `outcome.sharing`, and requires the floor finalization to verify. Failure is fatal. The scheme is registered for the floor's epoch.
3. **Tip verification against the trusted identity** (summary; normative rule: 07-consensus.md §8.3 "startup identity selection and tip check"): the trusted identity is the configured one (built-in: mainnet `{from_epoch: 2042, identity: 0x8627d337…a182}`, see 07-consensus.md), replaced by a persisted identity with a higher `from_epoch` (validators: from DKG state; followers: from the driver record, 9.3); a persisted identity with the same `from_epoch` but a different key is fatal. If the tip certificate's epoch ≥ `trusted.from_epoch` it MUST verify under the trusted identity, otherwise startup fails (an operator must configure a newer identity after a full-DKG rotation). If its epoch < `from_epoch` it is accepted as historical. The trusted identity is registered for `from_epoch`, and for the tip's epoch when verified; a later attempt to register a different key for either epoch is fatal.
4. **EL linkage**: when the floor is below the EL's finalized height, the executor starts from the EL's canonical block at the floor height and marshal re-delivers finalized blocks from the floor; each delivery must extend the EL's canonical chain (a `newPayload` that is not `VALID` for a finalized block is fatal, section 8). When the floor is above the EL's finalized height, the executor backfills from the EL's finalized height to the floor from the snapshot's contiguous prunable blocks (5.7).

The state root of the EL snapshot is thereby authenticated: it is in a header on the hash chain from the verified anchor/tip down to the EL's finalized block, and the EL executes every later finalized block on top of it.

After restore, the validator DKG manager has no persisted state and rebuilds it from the latest boundary outcome at or below the floor (07-consensus.md): its share comes, in order of preference, from `--consensus.signing-share` if it matches the outcome's public polynomial at its index, then from a salvaged stale share that matches, then by recovery from dealings revealed in the previous epoch's finalized dealer logs.

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

> **Resolved conflict C-P2P-02**: docs protocol/rpc/index.mdx says `consensus_subscribe` emits notarized, finalized and nullified events and `consensus_getLatest` returns the latest notarized block; the code emits only finalized events and always returns `notarized: null`. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-p2p-02).

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
3. If the startup floor (5.1.5) is in a later epoch than `b`'s outcome describes (the EL is behind consensus storage), let `p = epoch(floor) − 1`; if `p > epoch(b)` and marshal has the block `last(p)`, decode and register its outcome likewise and raise `current_epoch`. If marshal lacks it, continue: the node relies on the pinned identity fallback.

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

Marshal reports finalized tips (`FinalizedTip(round, height, digest)`, emitted once that finalization is readable from the finalization archive) and delivers finalized blocks in order (`FinalizedBlock`) to the follower executor (5.1.3), which processes one request at a time, blocks before tips.

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

**Floor advance**: after each completed request, if a tip was reported since the last advance (the first such tip's height is the *floor candidate*), the candidate is ≤ `el_finalized − epochLength`, and the EL has durably persisted the candidate block, the executor calls `set_floor` with the stored finalization at the candidate height (5.1.7). Marshal ignores it when its round is at or below marshal's round floor, which is the case once the candidate block was delivered and acknowledged; otherwise delivery restarts at the candidate block.

A follower's `head`, `safe` and `finalized` are always the same finalized block; followers never expose unfinalized blocks.

### 7.7 Uncertified follow mode (informative)

`--follow.nocertify` runs reth's debug consensus client against the upstream without certificate verification. Such a node trusts the upstream completely and is not a conforming follower.

## 8. Driving the EL (validators)

The validator executor separates **delivery** from **forkchoice**:

- `engine_newPayload` delivers a block and never moves the head. Notarized blocks, finalized blocks and verification probes are all deliveries.
- `engine_forkchoiceUpdated` (outside block building) sets `finalized = safe =` the latest delivered finalized block, and `head =` the *convergence target* (the parent selected by the latest consensus context, i.e. the notarized tip being built on) only if that target's own `newPayload` returned `VALID` and its ancestry was walked down to the current finalized tip; otherwise `head =` the finalized block.
- A finalized block whose `newPayload` is not `VALID`, a forkchoice update that is not `VALID`, and any engine call that fails outright are fatal.
- A finalized block is acknowledged to marshal only once the forkchoice update finalizing it was accepted **and** the EL has durably persisted it.
- Block building: fetch and deliver the parent, then `forkchoiceUpdated` with payload attributes on `VALID`. Verification probes and the `SYNCING` ancestor walk are specified in 07-consensus.md (validator verification procedure).
- A heartbeat forkchoice update is resent after `--consensus.fcu-heartbeat-interval` (default 5 min) without one.

So on a validator, the EL's `finalized`/`safe` tags are the latest finalized block and `latest` is the notarized tip the node is converging on, which is never behind `finalized`.

## 9. Persistence and crash safety

### 9.1 Logical stores

All consensus storage lives under the consensus data directory (`--consensus.datadir`, default `<datadir>/consensus`). A node keeps the logical stores below. Their on-disk layout, naming and encoding are implementation-defined; only what each store holds, and when it is durable, is normative.

| Store | Holds | Used by | In snapshot |
|---|---|---|---|
| Finalization archive | one finalization per height, by height and block digest; never pruned (5.2) | validator, follower | yes: anchor to tip (6.1) |
| Finalized-block store | recent finalized blocks above the EL's finalized height minus the retention; older blocks come from the EL (5.2) | validator, follower | yes: blocks above `execution_finalized_height` |
| Delivery metadata | marshal's processed height (5.1.1) | validator, follower | no |
| Consensus caches | per epoch: verified and notarized blocks, notarizations and finalizations by view, certified blocks by height (5.1.6) | validator, follower | no |
| Simplex journal | per epoch: the node's own votes and the artifacts it observed ([simplex.md §8.13](commonware/simplex.md#813-persistence)) | validator | no |
| DKG state | the DKG `State` of each epoch the node entered (9.2) | validator | no |
| DKG event journal | received dealings, acknowledgements, dealer logs and finalized-block markers, per epoch (9.2) | validator | no |
| Trusted-identity record | the follower's latest trusted network identity (9.3) | follower | no |

### 9.2 Validator requirements

A validator MUST satisfy all of the following across crashes and restarts:

1. **No equivocation.** Before sending a Simplex vote it MUST durably record it in the epoch's journal, and on restart it MUST replay the journal and never send a conflicting vote for a view it already voted in (07-consensus.md). Losing a journal (for example by restoring a snapshot, which never contains journals) while the epoch is still running risks equivocation; an operator MUST NOT run a validator whose journal for the current epoch was lost unless it is certain it sent no vote in that epoch's remaining views.
2. **DKG consistency.** It MUST durably persist, before acting on them: the per-epoch DKG `State` (`epoch`, transcript `seed`, `output`, `share`, `players`, an empty legacy `syncers` set, `is_full_dkg`) when it enters an epoch; every dealing it received as a player (so it never acknowledges two different dealings from one dealer); every acknowledgement it received as a dealer; every dealer log read from a finalized block; and finalized-block markers. It MUST NOT acknowledge differently after a restart. Events of epochs older than the previous one MAY be pruned.
3. **Ack after durability.** A finalized block MUST NOT be acknowledged to marshal (and so marked processed) until the EL has durably persisted it and accepted the forkchoice update finalizing it; marshal emits a block only after durably storing it with its finalization (5.1.3). On restart, marshal resumes delivery above its persisted processed height, or at the finalization archive's lowest entry when that is higher (5.1.5), and the executor first replays blocks from the EL's finalized height up to that point (5.7), so no finalized block is skipped by the EL.
4. **Startup checks** of 9.4 MUST pass before any actor starts.

> **Informative**: the encodings in this note are the reference implementation's local formats. They are not interoperable and another implementation MAY store this state differently; only the durability rules of item 2 are normative.
>
> Reference DKG state encoding (codec of [codec.md](commonware/codec.md); `Set` is [§6.1](commonware/codec.md#61-ordered-set), `Option` [§5.2](commonware/codec.md#52-option), tags [§5.6](commonware/codec.md#56-tagged-unions-enums)): `State := varint(epoch) || seed[32] || Output || ShareState || Set<ed25519>(players, 1..=65535) || Set<ed25519>(syncers, 0..=65535, always empty) || bool(is_full_dkg)`; `ShareState := 0x00 || Option<Share>` (plaintext; other tags are reserved). `Output` is [dkg.md §11.1](commonware/dkg.md#111-output) and `Share` is [cryptography.md §5.2](commonware/cryptography.md#52-share-encoding). Event journal entries: `0x00 || dealer || DealerPubMsg || DealerPrivMsg` (dealing), `0x01 || player || PlayerAck` (ack), `0x02 || dealer || DealerLog` (log), `0x03 || digest[32] || parent[32] || varint(height)` (finalized), with the messages of [dkg.md §5](commonware/dkg.md#5-messages) and `DealerLog` of [dkg.md §8.1](commonware/dkg.md#81-dealerlog-encoding).

On startup the DKG manager uses the persisted state if its epoch is at least the epoch of height `floor + 1`; otherwise it rebuilds the state from the chain as described at the end of 6.4.

### 9.3 Follower requirements

1. Marshal storage and the ack-after-processing rule as for validators, except that a follower acknowledges a block once its `newPayload` returned `VALID` or `SYNCING` and its forkchoice update was handled; the floor only advances to blocks the EL has durably persisted and that are at least one epoch behind the EL's finalized height (7.6).
2. The trusted-identity record holds `{from_epoch, identity}` (a 96-byte G2 network identity). It MUST be written durably before the follower relies on a changed identity (7.5). It is never part of a snapshot. Informative: the reference record is `0x01 || u64be(from_epoch) || G2[96]` (version 1, 105 bytes; G2 encoding [cryptography.md §4.3](commonware/cryptography.md#43-point-encoding-and-decoding)), a local format that other implementations need not share.
3. A follower MUST NOT move its EL forkchoice to a block that marshal has not stored together with its finalization (or as an ancestor of a stored finalization).

### 9.4 Startup consistency checks (both modes)

In order; any failure is fatal:

1. The finalization archive's tip certificate epoch equals `epoch(tip_height)`.
2. If the archive is empty, the EL's finalized height MUST be 0 (genesis start). If one of first/last index is set the other MUST be too. The first index MUST NOT be 0.
3. The tip header found at `tip_height` in the prunable store and, separately, in the EL (each only if present) MUST have number `tip_height` and hash equal to the tip certificate's payload.
4. If the floor is above genesis, the archive MUST contain the floor's finalization, and it MUST verify under the scheme built from the outcome at `boundary_for(floor.epoch)` (6.4 step 2).
5. The archive tip height MUST be ≥ marshal's stored processed height (otherwise consensus storage was overwritten with a stale snapshot).
6. Tip verification against the trusted identity (6.4 step 3); genesis MUST have no tip certificate and a tip MUST NOT be below the floor.
7. Validators: initial peer-set registration (2.4) MUST succeed.

### 9.5 Mode switching

An implementation MUST use the same marshal stores (9.1), in the same format, in both modes, so that a node MAY stop in one mode and restart in the other on the same data directory. A follower that becomes a validator also needs its ed25519 key, and either a share for the current epoch or recovery per 6.4.

## 10. Key and share files (informative)

| File | Format |
|---|---|
| `--consensus.signing-key` (plaintext) | `0x`-prefixed (or bare) hex of the encoding of the ed25519 private key (the 32-byte seed, [cryptography.md §3.1](commonware/cryptography.md#31-ed25519-encodings)), surrounding whitespace ignored |
| `--consensus.signing-key` with `--consensus.secret <path>` | an age (age-encryption.org/v1) scrypt passphrase-encrypted file whose plaintext is the raw 32-byte encoded ed25519 private key; the passphrase is read from `<path>` (a FIFO is preferred) |
| `--consensus.signing-share` | `0x`-prefixed hex of the share encoding of [cryptography.md §5.2](commonware/cryptography.md#52-share-encoding) (`varint(index) || scalar[32]`) |
| network identity override | `--consensus.network-identity <0x-hex 96-byte G2>` ([cryptography.md §4.3](commonware/cryptography.md#43-point-encoding-and-decoding)) with `--consensus.network-identity-from-epoch <u64>`; the built-in files `mainnet-network-identity.json` / `testnet-network-identity.json` are `{"from_epoch": u64, "identity": "0x" + 192 hex}` |

A configured share is used only if it matches the public polynomial of the latest finalized boundary outcome at the share's index (6.4; [cryptography.md §5.5](commonware/cryptography.md#55-partial-public-keys)).

## 11. Constants

| Constant | Value |
|---|---|
| Consensus p2p namespace | `0x05 \|\| "TEMPO_P2P"` (`union_unique(b"TEMPO", b"_P2P")`, [codec.md §7.2](commonware/codec.md#72-union_unique)); stream namespace `0x05 \|\| "TEMPO_P2P_STREAM"` ([p2p.md §11](commonware/p2p.md#11-constants)) |
| Scheme namespace | `b"TEMPO"` (07-consensus.md) |
| Channel ids | votes 0, certificates 1, simplex resolver 2, broadcast 3, marshal 4, DKG 5 |
| Channel quotas (per peer) | 128/s (0, 1, 2, 5), 8/s (3), 8/s default (4) |
| `max_message_size` default | 8,388,608 bytes |
| Peer-set refresh interval | 30 s |
| Tracked peer sets | 1 |
| Block broadcast deque | 10 per peer |
| Marshal resolver timeout / retry | 2 s / 100 ms |
| Prunable section size | 4,096 blocks (finalized-block store), 4,096 views (consensus caches) |
| Marshal `max_repair` | 20 |
| Marshal `view_retention` | 2,560 views (validators, default), 1 view (followers) |
| Muxer queues (each subchannel, channel-0 backup) | `--consensus.mailbox-size`, default 16,384 messages |
| `MINIMAL_PEER_SYNC_FINALIZED_BLOCKS` | 64,800 (= 3 × 21,600) |
| `tempo/1` | name `"tempo"`, version 1, 1 message, `NewFinalization = 0x00`, max frame 1,024 bytes |
| `tempo/1` limits | 8 frames/s per connection, 32 verifications/s, 256-frame queue, 2 connections per peer |
| Follower resolver backoff | 250 ms doubling to 30 s |
| FCU heartbeat | 5 min |
| Validator startup backfill FCU batch | 8 blocks |

## 12. Open conflicts

> **Resolved conflict C-P2P-01**: TIP-1017 says each validator's ed25519 key is "used for signing all consensus p2p messages"; the code signs Simplex votes and certificates with BLS12-381 threshold signatures and uses ed25519 only to authenticate the transport and to sign DKG artifacts. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-p2p-01).

> **Resolved conflict C-P2P-02**: docs protocol/rpc/index.mdx says `consensus_subscribe` emits notarized, finalized and nullified events and `consensus_getLatest` returns the latest notarized block; the code emits only finalized events and always returns `notarized: null`. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-p2p-02).

Section 2.1 states the code's behaviour for C-P2P-01 and section 7.2 for C-P2P-02. Neither affects block validity.
