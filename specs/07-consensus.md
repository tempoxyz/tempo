# 07 — Consensus

This chapter specifies Tempo's consensus layer: epochs, how blocks map onto Simplex proposals, the Simplex instantiation and its signing domains, leader election, finalization certificates and how followers verify them, the chain of trust in the network identity, the per-epoch DKG, the DKG artifacts carried in header `extra_data`, and the procedures validators follow to propose and to vote.

Transport, channel numbering, message framing on the wire, peer sets, backfill, the `tempo/1` RLPx subprotocol, follower block sources and persistence formats are in [08-p2p-and-sync.md](08-p2p-and-sync.md). Header field encodings (including `consensus_context`) are in [02-encoding.md](02-encoding.md). Execution-layer header and block checks (timestamps, the 10 KiB `extra_data` cap, the T8 committee system call) are in [05-block-execution.md](05-block-execution.md). The ValidatorConfigV2 and CurrentCommittee contracts are in [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md).

## 1. Roles and what each must implement

A **follower** trusts a block once it holds a valid finalization certificate for that block or a descendant. A follower MUST implement §2–§4, §7, §8 and the decoding of §10. It does not run Simplex, the DKG, or the proposal and voting rules.

A **validator** participates in Simplex and in the DKG. It MUST implement this whole chapter.

A rule marked *(validator voting rule)* decides whether an honest validator votes for a proposal. It is not checked when a finalized block is replayed. A finalized block that breaks such a rule is still part of the chain: the certificate is what makes it final.

## 2. Normative dependencies

Tempo's consensus is built from the components specified in the commonware chapters of this spec. A conforming client MUST reproduce their wire formats and algorithms bit for bit.

| Component | Specified in |
|---|---|
| Codec (varints, fixed-width integers, `bool`, `Option`, fixed arrays, length-prefixed sequences, decode bounds) | [codec.md §3–§5](commonware/codec.md#3-varint), decoding rules [§11](commonware/codec.md#11-decoding-rules) |
| Ordered sets (sorted and deduplicated; decoding rejects unsorted or duplicate items) | [codec.md §6.1](commonware/codec.md#61-ordered-set) |
| `union` (plain concatenation), `union_unique` (`varint(len(ns)) ‖ ns ‖ msg`), `modulo` (big-endian bytes mod n) | [codec.md §7.1](commonware/codec.md#71-union), [§7.2](commonware/codec.md#72-union_unique), [§7.3](commonware/codec.md#73-modulo) |
| Fault model `N3f1`: `f = (n − 1) / 3` (integer division), quorum `q = n − f` | [codec.md §8](commonware/codec.md#8-fault-model-n3f1) |
| Epoch, view, height and round; fixed-length epochs and phases | [codec.md §9.1](commonware/codec.md#91-epoch-view-height-and-round), [§10](commonware/codec.md#10-fixed-length-epochs) |
| Simplex BFT (data types, votes, certificates, view changes, locking, nullification, skip) | [simplex.md](commonware/simplex.md): types [§3](commonware/simplex.md#3-data-types-and-encodings), protocol [§8](commonware/simplex.md#8-protocol) |
| Threshold VRF signing scheme | [cryptography.md §6](commonware/cryptography.md#6-threshold-vrf-scheme); its use in Simplex: [simplex.md §4](commonware/simplex.md#4-signing), [§5](commonware/simplex.md#5-verification-and-assembly) |
| Leader election | [simplex.md §6](commonware/simplex.md#6-leader-election) |
| Marshal wrapper (epoch membership, parent linkage, boundary re-proposal) | [simplex.md §10](commonware/simplex.md#10-marshal-inline-wrapper) |
| BLS12-381 MinSig (signatures in G1, 48 bytes compressed; public keys in G2, 96 bytes compressed), hash-to-curve DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` | [cryptography.md §4](commonware/cryptography.md#4-bls12-381) (hash to curve [§4.4](commonware/cryptography.md#44-hash-to-curve), signing and verification [§4.5](commonware/cryptography.md#45-minsig-signing-and-verification)) |
| DKG and resharing | [dkg.md](commonware/dkg.md) |
| Public polynomial and share | [cryptography.md §5.4](commonware/cryptography.md#54-public-polynomial-and-sharing-encoding), [§5.2](commonware/cryptography.md#52-share-encoding); `Sharing` in a DKG output: [dkg.md §11.2](commonware/dkg.md#112-sharing) |
| Ed25519 (32-byte public keys ordered by their bytes; ZIP-215 verification) | [cryptography.md §3](commonware/cryptography.md#3-ed25519) |

Every BLS signature in this chapter is `bls_sign(sk, ns, msg)` of [cryptography.md §4.5](commonware/cryptography.md#45-minsig-signing-and-verification): the G1 hash of `union_unique(ns, msg)` under the DST above, multiplied by the secret scalar. Threshold partials ([cryptography.md §5.6](commonware/cryptography.md#56-partial-signatures)) sign the same message with a share.

## 3. Constants

| Name | Value | Notes |
|---|---|---|
| `NAMESPACE` | `b"TEMPO"` | Simplex scheme namespace and DKG `Info` namespace |
| Simplex vote namespaces | `b"TEMPO_NOTARIZE"`, `b"TEMPO_NULLIFY"`, `b"TEMPO_FINALIZE"`, `b"TEMPO_SEED"` | `union(NAMESPACE, suffix)` (§5.2) |
| P2P handshake namespace | `union_unique(b"TEMPO", b"_P2P")` | Used only by the transport; see [08-p2p-and-sync.md](08-p2p-and-sync.md) and [p2p.md §4.1](commonware/p2p.md#41-roles-identities-and-namespace) |
| `L` (epoch length) | 21,600 blocks on mainnet (4217) and on moderato (42431) | Genesis `config.epochLength`; see 01-chain-and-forks.md |
| Fault model | [`N3f1`](commonware/codec.md#8-fault-model-n3f1) | Simplex quorum and DKG thresholds |
| `MAX_VALIDATORS` | 65,535 (`2^16 − 1`) | Decode bound for player sets in `OnchainDkgOutcome` |
| `TEMPO_MAXIMUM_EXTRA_DATA_SIZE` | 10,240 bytes | EL cap on header `extra_data` (05-block-execution.md); every DKG artifact MUST fit |
| Mainnet network identity checkpoint | `from_epoch = 2042`, identity `0x8627d33753b0d90a8eae75363d6b393ab9204076545b3af6caf831903e4bedde4374f1106551b481fb5ea35e59d51c92165c963881c718216e3e4570a307c08885af55c274f19488f709afe021ca3d9e567138ab097860d9146e895407bea182` | Built-in mainnet checkpoint (§8.3) |
| Moderato network identity checkpoint | `from_epoch = 1747`, identity `0x967ae1a6d3ddbe5cb0fe5e6fc58e74249787b4a277619b549fed6609d04660540dd2449cd7174def35e40f544e5ad72d15d064191a205ed6e0c49619c68f975108b614d0d51def9a8416a10a07c4193bea0cbbc4252ec1b33f21095a5d7aa590` | Built-in moderato checkpoint (§8.3) |

On both networks the genesis timestamp is 0 and the genesis header `extra_data` is a 716-byte `OnchainDkgOutcome` for epoch 0 (§10.3).

## 4. Epochs

### 4.1 Mapping heights to epochs

Epochs have a fixed length `L` ([codec.md §10](commonware/codec.md#10-fixed-length-epochs)). With integer division:

```python
def epoch_of(h: int) -> int:        return h // L
def first(e: int) -> int:           return e * L
def last(e: int) -> int:            return e * L + L - 1
def is_boundary(h: int) -> bool:    return h % L == L - 1     # last block of its epoch
def relative(h: int) -> int:        return h - first(epoch_of(h))
def midpoint(e: int) -> int:        return first(e) + L // 2
```

Epoch 0 covers heights `[0, L−1]` and includes genesis (height 0). Genesis is not a boundary block, but it plays the role of epoch 0's *preceding boundary*: its `extra_data` carries the outcome for epoch 0, its hash is epoch 0's Simplex floor, and its timestamp is epoch 0's fork-selection timestamp.

The **boundary block of epoch e** is the block at `last(e)`. It MUST carry the `OnchainDkgOutcome` for epoch `e+1` (§10.2). Every other block of epoch `e` (heights `first(e)..last(e)−1`, genesis excluded) is a **regular block**; its `extra_data` is empty or one `SignedDealerLog` (§10.1).

Define, for every epoch `E`:

```python
def preceding_boundary_height(E):   return 0 if E == 0 else last(E - 1)
def boundary_timestamp(E):          return header(preceding_boundary_height(E)).timestamp   # seconds field
```

`boundary_timestamp(E)` selects the consensus-layer fork behaviour of epoch `E` (§6, §9.2, §15): "fork F is active for epoch E" means F is active at `boundary_timestamp(E)` under the predicate of 01-chain-and-forks.md. Because this uses a finalized block, every node chooses the same behaviour for an epoch whenever it enters it.

### 4.2 Phases

The phase of a height within its epoch ([codec.md §10.2](commonware/codec.md#102-phases)):

| Phase | Condition | Mainnet heights in epoch `e` (`L = 21600`) |
|---|---|---|
| `Early` | `relative(h) < L // 2` | `first(e) … first(e) + 10799` |
| `Midpoint` | `relative(h) == L // 2` | `first(e) + 10800` |
| `Late` | `relative(h) > L // 2` | `first(e) + 10801 … last(e)` |

Phases drive DKG timing (§9.4). They do not affect block validity.

## 5. Simplex instantiation

### 5.1 Block ↔ proposal mapping

- The Simplex **digest** of a block is its 32-byte block hash `keccak256(rlp(TempoHeader))` (02-encoding.md). It is encoded as 32 raw bytes ([simplex.md §3.2](commonware/simplex.md#32-digest)).
- A **Proposal** is `{round: Round(epoch, view), parent: View, payload: Digest}`, encoded as `varint(epoch) ‖ varint(view) ‖ varint(parent_view) ‖ payload[32]` ([simplex.md §3.3](commonware/simplex.md#33-proposal)).
- A block's **parent digest** is `header.parent_hash` and its **height** is `header.number`.
- The Simplex **Context** of a proposal is `{round: (epoch, view), leader: ed25519 public key, parent: (parent_view, parent_digest)}` ([simplex.md §3.4](commonware/simplex.md#34-context)).
- On the consensus network a block travels as the raw RLP of the sealed execution block (header and body), with no other framing. A receiver MUST reject an encoding that does not decode, whose body does not match the header commitments (transactions root, withdrawals root and the other body checks of 05-block-execution.md), or whose header contains a `block_access_list_hash`.

#### Header consensus context

Every block a validator proposes carries `header.consensus_context = {epoch, view, parent_view, proposer}` (TIP-1031; encoding in [02-encoding.md §2.3](02-encoding.md#23-tempoconsensuscontext)), equal to the Context the block was **first proposed under**: `epoch` and `view` of that proposal's round, `parent_view` of its parent, and `proposer` = that round's leader as 32 raw Ed25519 bytes. No rule compares it with the round of the certificate that notarizes or finalizes it; a re-proposed boundary block keeps its first proposal's context (§5.3). On mainnet and Moderato the genesis header and every header before T4 have no `consensus_context`, and every non-genesis header from T4 has one.

Presence by fork is a header-validity rule ([02-encoding.md §2.5](02-encoding.md#25-standalone-header-validity) check 9): a header MUST NOT contain the context before T4 and MUST contain it from T4, by block timestamp. Every node checks it, including followers replaying finalized blocks. A validator voting on a new proposal from T4 MUST also require that the context equals the engine's Context for it (§13 step 5).

> **Resolved conflict C-CONS-01**: TIP-1031 requires the context to be absent before T4 and the check to depend on activation, but the implementation has no T4 gate: it always builds and requires a context. Decided: this spec adopts TIP-1031's rule, and every node checks presence by fork as a header-validity rule. The implementation does not yet enforce the gate, and that is tracked as a code issue. Mainnet and Moderato history satisfy the rule. See [conflicts](conflicts.md#c-cons-01).

Every mainnet block a validator votes on under T13 rules has its timestamp after T4, so the rule above (present and equal) applies to them. A block whose header has no context MUST fail the check: a validator rejects it, whatever placeholder Context it uses internally.

### 5.2 Signing scheme and signing domains

Each epoch's Simplex instance uses the threshold VRF scheme over BLS12-381 MinSig ([cryptography.md §6](commonware/cryptography.md#6-threshold-vrf-scheme)), with Ed25519 participant keys and namespace `NAMESPACE = b"TEMPO"`:

- **Participants** of epoch `E` are `outcome(E).output.players`, the ordered set of Ed25519 keys from the outcome that opened `E` (§8.2). A participant's index is its position in that set.
- **Group public key** (network identity) of epoch `E` is `outcome(E).output.public.public()`, the constant term of the public polynomial (96-byte G2; [cryptography.md §5.4](commonware/cryptography.md#54-public-polynomial-and-sharing-encoding)).
- A validator with a share for epoch `E` is a **signer**; any other node runs the epoch as a **verifier**.

Each vote carries two threshold partial signatures made with the signer's share: a *vote signature* and a *seed signature*. Each certificate carries the two recovered threshold signatures. The signed messages (each hashed as `union_unique(ns, msg)`, §2; namespaces and subjects as in [simplex.md §4](commonware/simplex.md#4-signing)) are:

| Subject | Vote namespace `ns` | Vote message | Seed namespace | Seed message |
|---|---|---|---|---|
| Notarize / Notarization | `b"TEMPO_NOTARIZE"` | `encode(Proposal)` | `b"TEMPO_SEED"` | `encode(proposal.round)` |
| Nullify / Nullification | `b"TEMPO_NULLIFY"` | `encode(Round)` | `b"TEMPO_SEED"` | `encode(Round)` |
| Finalize / Finalization | `b"TEMPO_FINALIZE"` | `encode(Proposal)` | `b"TEMPO_SEED"` | `encode(proposal.round)` |

`encode(Round)` is `varint(epoch) ‖ varint(view)`. A certificate is valid iff both recovered signatures verify against the epoch's group public key ([cryptography.md §6.5](commonware/cryptography.md#65-verifying-certificates); the two MAY be batch-verified, [§4.6](commonware/cryptography.md#46-batch-verification)). The threshold is the `N3f1` quorum `q = n − f` of the epoch's `n` participants ([codec.md §8](commonware/codec.md#8-fault-model-n3f1)), and so is the number of votes needed for each certificate ([cryptography.md §6.6](commonware/cryptography.md#66-assembling-a-certificate)).

Ed25519 keys sign no Simplex votes. They authenticate p2p connections (08-p2p-and-sync.md), DKG acknowledgements and dealer logs (§9), and ValidatorConfigV2 operations.

### 5.3 Epoch-scoped instances

Each epoch `E` runs its own Simplex instance with this configuration (parameter meanings and constraints: [simplex.md §7](commonware/simplex.md#7-engine-configuration)):

| Parameter | Value | Interop-relevant |
|---|---|---|
| `epoch` | `E` | yes |
| `floor` | a genesis floor at view 0 whose digest is `hash(preceding_boundary_height(E))`: the hash of block `last(E−1)`, or the genesis hash for `E = 0` | yes |
| `scheme` | §5.2 with the participants and polynomial of `outcome(E)` | yes |
| `elector` | the Random elector (SHA-256) with version `version(E)` (§6) | yes |
| `leader_timeout` | 1,200 ms | no (liveness) |
| `certification_timeout` | 2 s | no |
| `timeout_retry` (nullify rebroadcast) | 10 s | no |
| `fetch_timeout` | 2 s | no |
| `view_retention` (activity timeout) | 256 views | no |
| `skip` | enabled, skip timeout 11.2 s, skip budget `n` (the number of participants) | no |
| `forward` | disabled | no |
| `track_historical_votes` | true | no |

Parameters marked "no" are local policy. Validators SHOULD use the listed values, because very different timeouts harm liveness, but they do not change which blocks are valid. The engine requires `certification_timeout > leader_timeout`, and `skip.timeout` greater than both `certification_timeout` and `timeout_retry`.

Within an epoch, views start at 1. The floor sits at view 0. The first block of epoch `E` therefore has height `first(E)`, `parent_hash = hash(last(E−1))` and `consensus_context.parent_view = 0`. Epoch 0's first block is height 1, with genesis as parent.

Block-to-epoch membership *(validator voting rule)*: a proposal in round `(E, v)` is acceptable only if its block's height is in epoch `E`. Its parent must be the block named by the context's parent digest, with height exactly one less (§13).

**Boundary re-proposal.** When the parent chosen for a proposal in epoch `E` is the boundary block `last(E)`, the leader MUST NOT build a new block. It re-proposes the boundary block: the proposal's payload equals `context.parent.1`, the parent digest. A proposal whose payload equals its parent digest is valid iff the block it names has height `last(E)`. The application does not verify it again ([simplex.md §10.2](commonware/simplex.md#102-verifyctx-d)). So the boundary block can be notarized and finalized in a later view than the one recorded in its header `consensus_context`, and no block above `last(E)` is ever proposed in epoch `E`.

**Certification (Before T14).** The verification mode is *immediate*: the application's verify (§13) completes before the node sends its notarize vote, and certify returns once the block is available locally. (Deferred verification, the default from T14, is out of scope. TIP-1031 lets a validator keep synchronous verification in any case.)

## 6. Leader election

The leader of round `(E, v)` is participant `players[idx]` of epoch `E` (§5.2), where `n = len(players)`:

```python
def leader_index(E: int, v: int, n: int, seed_sig: bytes | None, version: str) -> int:
    # seed_sig: the 48-byte compressed G1 seed signature of round (E, v-1), taken from the
    # first valid certificate (notarization, nullification or finalization) of view v-1 that
    # the node obtained. It is None only for v == 1.
    if seed_sig is None:
        assert v == 1
        return (E + v) % n
    if version == "V0":
        return modulo(seed_sig, n)            # int.from_bytes(seed_sig, "big") % n
    else:  # "V1"
        return modulo(sha256(seed_sig), n)
```

`modulo` is defined in [codec.md §7.3](commonware/codec.md#73-modulo) and the seed in [cryptography.md §6.7](commonware/cryptography.md#67-seed). A node sets the leader of view `v` as soon as it holds a valid certificate of view `v−1`, which may be before it enters `v` ([simplex.md §6](commonware/simplex.md#6-leader-election), [§8.9](commonware/simplex.md#89-handling-certificates)). The seed signature of a round is the same whichever certificate kind carries it, so every honest node chooses the same leader.

Version selection:

- **Before T12** (T12 not active at `boundary_timestamp(E)`): version `V0` of [simplex.md §6](commonware/simplex.md#6-leader-election).
- **From T12** (T12 active at `boundary_timestamp(E)`): version `V1` (TIP-1116 §5).

The version is fixed for the whole epoch. The first epoch of mainnet that uses V1 is the first `E` whose block `last(E−1)` has `timestamp ≥ 1791900000`.

## 7. Certificates and follower verification

### 7.1 Encodings

Encoded with the codec of [codec.md](commonware/codec.md), as restated from [simplex.md §3.7](commonware/simplex.md#37-certificates):

```text
Round          = varint(epoch:u64) ‖ varint(view:u64)
Proposal       = Round ‖ varint(parent_view:u64) ‖ payload[32]
VrfCertificate = vote_signature[48] ‖ seed_signature[48]        # compressed G1 points, read raw
Notarization   = Proposal ‖ VrfCertificate
Finalization   = Proposal ‖ VrfCertificate
Nullification  = Round ‖ VrfCertificate
```

A follower decoding a `Finalization` MUST consume the input exactly. Decoding reads each signature as 48 raw bytes. The G1 point checks (valid compressed encoding, on the curve, in the subgroup; [cryptography.md §4.3](commonware/cryptography.md#43-point-encoding-and-decoding)) run at verification: a signature that fails them makes the certificate invalid (§7.2), not undecodable ([cryptography.md §6.2](commonware/cryptography.md#62-certificate-signature-pair), [simplex.md §3.8](commonware/simplex.md#38-decoding-rules)). The framings that carry certificates (the `tempo/1` `NewFinalization` frame, RPC responses, the marshal resolver) are in 08-p2p-and-sync.md.

### 7.2 Verification algorithm

A follower keeps `keys: Map[epoch → G2]`, the trusted group keys (§8). To accept a finalization `fin` for a block `B`:

```python
def verify_finalization(fin: Finalization, B: Block) -> None:
    check_body_matches_header(B)                       # 05-block-execution.md
    require(fin.proposal.payload == block_hash(B.header))
    E = fin.proposal.round.epoch
    require(E == epoch_of(B.header.number))            # re-proposals never leave the epoch
    key = trusted_key(E)                               # §8.3; raises IdentityUnavailable
    require(bls_verify(key, union_unique(b"TEMPO_FINALIZE", encode(fin.proposal)), fin.vote_signature))
    require(bls_verify(key, union_unique(b"TEMPO_SEED",     encode(fin.proposal.round)), fin.seed_signature))
```

`bls_verify` fails for a signature whose bytes are not a valid G1 point. This is `verify_certificate` of [cryptography.md §6.5](commonware/cryptography.md#65-verifying-certificates) for the finalize subject.

A valid finalization of `B` finalizes `B` and, through the `parent_hash` chain, every ancestor of `B`. A follower MAY skip certificates for intermediate blocks. It MUST take the ancestors' bodies by following `parent_hash` from `B` down to its last finalized block, checking that each block hashes to the digest its child names. Two valid finalizations for different blocks at the same height cannot exist unless more than `f` participants of the epoch are faulty. A follower that sees them SHOULD stop rather than choose one.

Validators verify finalizations, notarizations and nullifications received over the network with the same keys and namespaces. A validator MAY accept a finalization or notarization for any epoch whose key it holds, including straggler certificates for an epoch it already left. After it leaves epoch `E`, it holds the keys of `E−1`, `E` and `E+1` (§14).

## 8. Trust chain and network identity

### 8.1 Root of trust

A client's root of trust is the genesis hash from the chain specification (04-state-and-genesis.md) together with its network identity checkpoint (§8.3), which every client has. Every node also reads `outcome(0) = OnchainDkgOutcome.read(genesis.extra_data)`, whose `epoch` MUST be 0, and installs `keys[0]` from it when it starts from genesis.

When the chain ships no checkpoint, the checkpoint is `{from_epoch: 0, identity: outcome(0).output.public.public()}`, so the root of trust is the genesis block alone. A client then verifies every epoch's certificates under the genesis identity until one fails, and from there installs keys one boundary at a time (§8.3).

With the built-in mainnet checkpoint (`from_epoch = 2042`), the root of trust for mainnet history is that checkpoint plus the genesis hash. A client verifies one finalization of an epoch `≥ 2042` under the checkpoint and authenticates every earlier block through the `parent_hash` chain (§7.2). It needs no certificate of epochs 0 to 2041. No node is required to keep or serve one ([08-p2p-and-sync.md §5.5](08-p2p-and-sync.md#55-retention-guarantees)), so a client can't count on checking the checkpoint itself against the network. When a finalization of block `last(2041)` is available, a client can check the checkpoint from genesis: that finalization verifies under the genesis identity (epochs 0 to 2041 share it, because every ceremony before epoch 2041 was a reshare), and the block it finalizes carries `outcome(2042)`. This check trusts the genesis identity as a fallback in the sense of §8.3.

> Informative: at the time of writing, the public mainnet RPC (08-p2p-and-sync.md §7.2) serves the finalization of block 44,107,199 (`last(2041)`, epoch 2041, view 21,608) but not that of block 21,599 (`last(0)`).

### 8.2 Per-epoch keys from boundary blocks

For every epoch `E`, once the boundary block `b = last(E)` is final:

```python
def install_from_boundary(b: Block) -> None:
    require(is_boundary(b.header.number))
    o = OnchainDkgOutcome.read(b.header.extra_data)     # prefix decode, §10.2
    require(o.epoch == epoch_of(b.header.number) + 1)
    install(o.epoch, o.output.public.public())

def install(E: int, key: G2) -> None:
    if E in keys and keys[E] != key:
        fatal("conflicting network identity for epoch E")   # never replace a trusted key
    keys[E] = key
```

`outcome(E+1)` also fixes epoch `E+1`'s participants (`o.output.players`), the next DKG's players (`o.next_players`) and whether that DKG is a full one (`o.is_next_full_dkg`). A follower can only verify epoch `E+1`'s certificates after it has finalized and decoded block `last(E)` (or holds a checkpoint, §8.3). It therefore moves through epochs one boundary at a time.

**Reshare and full DKG.** In a resharing ceremony (§9) the group key stays the same: `keys[E+1] == keys[E]`. A full DKG (when `outcome(E).is_next_full_dkg` is true, so the ceremony during `E` has no previous output) produces a new key, the *network identity rotation*, which takes effect in epoch `E+1` if the ceremony succeeds. If it fails, the key stays the same. A follower MAY check that `keys[E+1] != keys[E]` implies `outcome(E).is_next_full_dkg`. It MUST NOT depend on this.

### 8.3 Network identity checkpoints

Every client has exactly one configured checkpoint `NetworkIdentity = {from_epoch: u64, identity: G2}`. It is the checkpoint the client ships for the chain, an operator-configured one that replaces it, or, when neither exists, the genesis checkpoint `{from_epoch: 0, identity: outcome(0).output.public.public()}` (§8.1). A chain whose genesis carries no decodable outcome and that has no configured checkpoint can't be followed or validated. Its JSON form is exactly `{"from_epoch": <u64>, "identity": "0x<192 hex chars>"}` (no other fields), where `identity` is the 96-byte compressed G2 group key, which MUST decode as a valid G2 point ([cryptography.md §4.3](commonware/cryptography.md#43-point-encoding-and-decoding)). The mainnet and moderato values are in §3. Each one is the identity produced by the network's most recent full DKG at the time of the release, and from_epoch is the epoch whose certificates it first verifies.

#### Startup identity selection and tip check

A client persists the latest identity it derived from the chain as `{from_epoch, identity}` (validators in their DKG state, followers in their trusted-identity record, 08-p2p-and-sync.md §9). At startup it selects its trusted identity `trusted`:

```python
trusted = configured_checkpoint
if persisted is not None:
    if persisted.from_epoch == configured_checkpoint.from_epoch:
        require(persisted.identity == configured_checkpoint.identity)   # else fatal
    if persisted.from_epoch > configured_checkpoint.from_epoch:
        trusted = persisted
```

and then checks its locally stored finalized tip, if any. A tip whose certificate epoch is `≥ trusted.from_epoch` MUST verify against `trusted.identity`, which is then installed for that epoch. If it fails, startup fails, and the operator must configure a newer checkpoint. A tip from an earlier epoch is accepted as local history without verification. A certificate at height 0 is fatal, and a client without a stored tip MUST be at genesis. Finally `install(trusted.from_epoch, trusted.identity)`. A key later derived from the chain for `trusted.from_epoch` must agree with it, or the client stops.

`trusted` stays fixed until the next restart. An identity the client installs from a boundary during the run (§8.2) is persisted (08-p2p-and-sync.md §7.5), but it becomes `trusted` only at the next startup.

#### Fallback verification

```python
def trusted_key(E: int) -> G2:
    if E in keys:
        return keys[E]
    if E >= trusted.from_epoch:
        return trusted.identity         # fallback
    raise IdentityUnavailable(E)
```

A finalization that verifies under the fallback installs `trusted.identity` as `keys[E]` for its epoch. A boundary that later yields a different key for that epoch is a conflict, which is fatal (§8.2).

When verification under the fallback fails, the identity may have rotated. Let `current_epoch` be the highest epoch whose key the client installed from a boundary. If the certificate's epoch is above `current_epoch`, the client fetches the finalization of `last(current_epoch)`, which verifies under `keys[current_epoch]`, and installs the next key from that block (§8.2). It repeats this one boundary at a time until `current_epoch` reaches the certificate's epoch (08-p2p-and-sync.md §7.4, §7.5). A key installed from the checkpoint or through the fallback doesn't count toward `current_epoch`, so the walk starts from the client's latest processed boundary even when that is far below `trusted.from_epoch`. A client in that position needs boundary finalizations of epochs below the checkpoint, which no node is required to serve (§8.1); when none is served it makes no progress and reports no error until the operator configures a checkpoint at or after the latest rotation ([08-p2p-and-sync.md §7.4](08-p2p-and-sync.md#74-verification)). A client with the genesis checkpoint crosses every rotation since genesis this way. A certificate whose epoch is below `trusted.from_epoch` and has no installed key raises `IdentityUnavailable`, and the client doesn't use it. With the genesis checkpoint this never happens.

For epochs above `trusted.from_epoch` the checkpoint is only a fallback. When an on-chain outcome for such an epoch carries a different key, the chain-derived key is installed for that epoch, and the client SHOULD warn that its configured checkpoint is outdated.

**Security of the fallback.** Fallback acceptance trusts that no quorum of shares of the group secret behind `trusted.identity` signs a false finalization. Resharing keeps the secret, so this covers every committee that ever held shares of it, including committees of earlier epochs that have since left. Within one run the fallback stays `trusted.identity`, even after the client installed a newer key from a rotation at epoch `R > trusted.from_epoch`. Until it restarts, it accepts a certificate for any later epoch whose key it hasn't installed if the certificate verifies under the replaced identity, and such a certificate can drive it to a block the current committee never finalized. Keeping the configured checkpoint current, and restarting after a rotation, limits this exposure.

> Informative: the mainnet checkpoint (`from_epoch = 2042`) means a full DKG ran during epoch 2041. Its identity differs from the genesis identity.

## 9. Distributed key generation

Each epoch runs one Feldman–Desmedt ceremony ([dkg.md](commonware/dkg.md); fault model `N3f1` and derived thresholds in [dkg.md §2](commonware/dkg.md#2-fault-model-and-derived-parameters)). The ceremony run during epoch `E` produces the output that `outcome(E+1)` carries.

### 9.1 Roles

Let `S(E)` be the DKG state of epoch `E`, taken from `o = outcome(E)` (the outcome in block `preceding_boundary_height(E)`):

| Field | Value |
|---|---|
| `S.epoch` | `E` (= `o.epoch`) |
| `S.output` | `o.output` |
| `S.dealers` | `o.output.players`: the epoch's consensus committee |
| `S.players` | `o.next_players` |
| `S.is_full_dkg` | `o.is_next_full_dkg` |

**Dealers** are the current committee. **Players** are the validators chosen from ValidatorConfigV2 at the previous boundary (§11), who become epoch `E+1`'s committee if the ceremony succeeds. A key may be both.

### 9.2 Round information

```python
info(E) = Info.new[N3f1](
    namespace = b"TEMPO",
    round     = E,
    previous  = None if S.is_full_dkg else S.output,
    mode      = Mode.NonZeroCounter,
    reveal    = Reveal.V1 if T12 active at boundary_timestamp(E) else Reveal.V0,
    dealers   = S.dealers,
    players   = S.players,
)
```

`Reveal::V0` applies before T12 and `Reveal::V1` from T12 (TIP-1116 §4), keyed on the ceremony's starting boundary exactly like the elector (§6). `Info`, its validity and the reveal thresholds are defined in [dkg.md §3](commonware/dkg.md#3-round-information) and [§2](commonware/dkg.md#2-fault-model-and-derived-parameters). The reveal version enters the round's transcript summary ([dkg.md §3.3](commonware/dkg.md#33-round-summary)), so acks, dealer logs and outputs from rounds of different versions are incompatible. In a resharing round each dealer deals from its current share. In a full round (`previous = None`) dealers deal fresh secrets. A dealer without a share in a resharing round does not deal.

### 9.3 DKG messages

DKG messages travel on the DKG channel, multiplexed by `u64` epoch (08-p2p-and-sync.md). A message's payload is:

```text
DkgMessage = 0x00 ‖ DealerPubMsg ‖ DealerPrivMsg      # dealer → one player
           | 0x01 ‖ PlayerAck                         # player → dealer
```

The envelope is [dkg.md §5.4](commonware/dkg.md#54-tempo-dkg-channel-envelope) and the messages are [`DealerPubMsg`](commonware/dkg.md#51-dealerpubmsg), [`DealerPrivMsg`](commonware/dkg.md#52-dealerprivmsg) and [`PlayerAck`](commonware/dkg.md#53-playerack). `DealerPubMsg` is read with `cfg = len(S.players)`. The whole payload MUST decode exactly, and any other tag is invalid. A node SHOULD block a peer that sends an undecodable message or an invalid dealing.

### 9.4 Timing (validator behaviour)

The DKG is driven by **finalized** blocks of epoch `E`, in height order:

1. **Early phase.** For each finalized block in `Early`, a dealer (re)sends `Dealer(pub, priv_p)` to every player `p` that has not yet acked. A dealer that is also a player processes its own dealing locally.
2. **Players.** When a player receives a valid dealing from a dealer for the first time, it MUST persist the dealing before it returns `Ack`. It MUST return the same ack for any later copy, and MUST NOT ever ack a different dealing from the same dealer in the same round ([dkg.md §7.1](commonware/dkg.md#71-verifying-a-dealing), [§7.2](commonware/dkg.md#72-when-to-acknowledge)).
3. **Acks.** A dealer accepts the first ack from each player, and persists it, until it finalizes. If that first ack is invalid, the dealer stops retrying that player ([dkg.md §6.2](commonware/dkg.md#62-receiving-acknowledgements)).
4. **Midpoint and later.** On the first finalized block in `Midpoint` or `Late` (or at startup when the latest finalized block of the epoch is past `Early`), a dealer finalizes its `SignedDealerLog`: its commitment plus, for each player, the ack or the revealed share ([dkg.md §6.3](commonware/dkg.md#63-finalizing-the-dealer-log)).
5. **Posting.** Whenever the dealer is the leader of a round of epoch `E` and proposes a regular block, it includes its own finalized log as `extra_data` (§10.1). It does this in every such proposal until it observes the log in a finalized block.
6. **Conclusion.** At the boundary, the output is computed from the logs on chain (§11.1).

Nothing in block validity enforces these timings. For example, a log that appears before the midpoint is still valid.

A validator MUST persist, per epoch, the dealings it received and the acks it gave, and MUST persist the new DKG state (epoch, output, share, players, is_full_dkg) before it enters the next epoch. Otherwise it may equivocate after a restart. The durability requirements are in 08-p2p-and-sync.md §9.2; on-disk formats are implementation-defined.

### 9.5 Share recovery (informative)

A validator that starts without usable DKG state for epoch `E` (for example after restoring a snapshot) takes its share for `E`, in order of preference, from a configured share, from a share salvaged from stale state, or by recovery from finalized history. The first two are used only if their public share matches the partial public key of their index in `outcome(E).output.public` ([cryptography.md §5.5](commonware/cryptography.md#55-partial-public-keys)).

Recovery from finalized history lacks the player's private dealings, which never appear on chain, so it works only when every selected dealer's log revealed this player's share. Its preconditions are:

- the validator is in `outcome(E).output.players`;
- the ceremony of `E−1` succeeded (`outcome(E).output != outcome(E−1).output`), and the validator was one of its players;
- for each dealer in `outcome(E).output.dealers`, a log that decodes and passes `check(info(E−1))` (§10.1) appears in blocks `first(E−1)…last(E−1)−1`. The first such log per dealer is used.

It then runs [dkg.md §12](commonware/dkg.md#12-player-share-derivation) on those logs with no private dealings. If a selected log carries this player's acknowledgement instead of a reveal, the player's share from that dealer is missing and recovery fails. The validator then runs epoch `E` without a share. A rebuilt output that differs from `outcome(E).output` is an error, and no share is used.

## 10. On-chain DKG artifacts

All decoding below is **prefix decoding**: a node reads the artifact from the start of `extra_data` and ignores any trailing bytes. Proposers MUST encode the artifact exactly, with no trailing bytes. Implementations MUST NOT reject an artifact only because trailing bytes follow it, or they would vote differently from other validators.

### 10.1 `SignedDealerLog` in regular blocks

```text
extra_data (regular block) = empty
                           | SignedDealerLog                                  # read with cfg = len(S(E).players)
SignedDealerLog            = dealer:ed25519_public_key[32] ‖ DealerLog ‖ sig:ed25519_signature[64]
DealerLog                  = DealerPubMsg ‖ results                           # per-player ack or reveal
```

The layouts are [dkg.md §8.2](commonware/dkg.md#82-signeddealerlog) and [§8.1](commonware/dkg.md#81-dealerlog-encoding). `SignedDealerLog.check(info(E))` verifies the dealer's Ed25519 signature over the log's transcript, which is bound to `info(E)` ([dkg.md §4](commonware/dkg.md#4-transcripts-and-signatures), [§8.3](commonware/dkg.md#83-validating-a-log-against-the-round)). It returns `(dealer, log)` or fails.

Inclusion rule *(validator voting rule)*, for a regular block proposed in round `(E, v)` with leader `ℓ`:

1. If `extra_data` is empty, accept.
2. Otherwise `extra_data` MUST decode as a `SignedDealerLog` for epoch `E` and pass `check(info(E))`, and the returned `dealer` MUST equal `ℓ`. Anything else is a reject.
3. If the validator's DKG state is not at epoch `E`, so it cannot check the log, it abstains (§13).

The ceremony itself (§11.1) ignores regular-block `extra_data` that fails to decode or to check, wherever it appears. For each dealer, the first log on `P`'s ancestry that decodes and passes `check(info(E))` is that dealer's log, whatever its later classification in [dkg.md §9](commonware/dkg.md#9-log-collection-and-selection) and [§10](commonware/dkg.md#10-computing-the-output) (for example faulty). Every later log from the same dealer is ignored, even a valid one.

### 10.2 `OnchainDkgOutcome` in boundary blocks

```text
OnchainDkgOutcome =
    varint(epoch:u64)                                    # the epoch this outcome opens
  ‖ Output                                               # decode bounds: max_participants = 65535, mode version 0
  ‖ set(ed25519_public_key) next_players                # varint(len) ‖ 32-byte keys, strictly increasing, 1 ≤ len ≤ 65535
  ‖ bool is_next_full_dkg                                # one byte, 0x00 or 0x01

Output = Summary[32] ‖ Sharing public ‖ set dealers (1..=65535)
       ‖ set players (1..=65535) ‖ set revealed (0..=65535)
```

`Output` is specified in [dkg.md §11.1](commonware/dkg.md#111-output), sets in [codec.md §6.1](commonware/codec.md#61-ordered-set). `Sharing` is `mode:u8 ‖ total:u32_be ‖ Poly<G2>`, the public polynomial with its mode version and participant total ([dkg.md §11.2](commonware/dkg.md#112-sharing), [cryptography.md §5.4](commonware/cryptography.md#54-public-polynomial-and-sharing-encoding)). Its decoder does not check that `total` equals the number of players or the polynomial's length; dkg.md §11.2 says how such an output is handled. Its constant term is the network identity. `players` is the committee of epoch `epoch`. `dealers` are the dealers whose logs formed the output. `revealed` lists the players whose shares were revealed.

The boundary block `last(E)` MUST carry, as `extra_data`, the encoding of the outcome given by §11 for its parent. `epoch` MUST be `E+1`.

- *(validator voting rule)* A validator rejects a boundary proposal whose `extra_data` does not decode as an `OnchainDkgOutcome`, or whose decoded outcome differs from its own computation (§13).
- **From T8**, block execution also decodes the boundary outcome for the CurrentCommittee system call, and a block that fails this decode is invalid for every node (05-block-execution.md). **Before T8**, block execution does not read `extra_data`.

Every node treats a *finalized* boundary block without a decodable outcome as a fatal inconsistency.

**Size.** The encoding MUST fit within 10,240 bytes (§3). It takes 32 bytes per key in each of the four key sets (`dealers`, `players`, `revealed`, `next_players`), 96 bytes per polynomial coefficient (`q` coefficients for a committee of `n`), and under 20 bytes of fixed fields and length prefixes. When the committee, the selected dealers and the next players are the same `n` validators, the outcome fits for `n ≤ 63` with no revealed players and for `n ≤ 59` with `f(n)` revealed players. A `SignedDealerLog` (§10.1) takes 96 bytes per commitment coefficient, 32 bytes per player key, 65 bytes per acknowledgement and 33 bytes per reveal, plus about 100 bytes of dealer key, signature and length prefixes. It fits for up to 63 players when every player acknowledges.

Neither ValidatorConfigV2 nor consensus limits the number of active validators. If `next_players` makes the outcome exceed the cap, no valid boundary block exists and the chain can't extend past `last(E) − 1`. A dealer log that exceeds the cap makes every block that carries it invalid, so it never lands on chain and that dealer is missing from the ceremony. Mainnet committees have had at most 19 members through epoch 2201.

### 10.3 Genesis

The genesis header `extra_data` is an `OnchainDkgOutcome` with `epoch = 0`: epoch 0's committee and identity, the players of the ceremony run during epoch 0, and `is_next_full_dkg`. On mainnet and moderato it is 716 bytes: 4 players, polynomial quorum 3, and 4 next players. The genesis `consensus_context` is absent.

## 11. Deterministic boundary outcome

Given the parent `P` of a boundary block, with `P.number = last(E) − 1`, every honest validator computes the same `OnchainDkgOutcome`:

```python
def boundary_outcome(P: Block) -> OnchainDkgOutcome:
    E = epoch_of(P.number)
    S = dkg_state(E)                                 # §9.1
    output = ceremony_output(E, P)                   # §11.1
    vc = ValidatorConfigV2 at the post-state of P    # state after executing P, P not necessarily canonical
    next_players = active_players(vc)                # §11.2
    rotation_epoch = vc.getNextNetworkIdentityRotationEpoch()   # see precompiles/validator-config-and-zones.md
    return OnchainDkgOutcome(
        epoch = E + 1,
        output = output,
        next_players = next_players,
        is_next_full_dkg = (rotation_epoch == E + 1),
    )
```

The outcome depends on the post-state of the *parent*, not on the boundary block's own transactions. A change to ValidatorConfigV2 made in block `last(E)` itself is first seen at the next boundary.

### 11.1 Ceremony output

```python
def ceremony_output(E: int, P: Block) -> Output:
    logs = {}                                        # dealer -> DealerLog
    for B in ancestors_ascending(P, from_height=max(first(E), 1), to_height=P.number):   # inclusive; genesis excluded
        if B.extra_data == b"":
            continue
        r = try_decode_signed_dealer_log(B.extra_data, cfg=len(S.players))  # prefix decode
        if r is None:
            continue
        checked = r.check(info(E))
        if checked is None:
            continue
        dealer, log = checked
        if dealer not in logs:
            logs[dealer] = log                       # the oldest log per dealer on P's ancestry wins
    ceremony = Logs(info(E))                         # dkg.md §9
    for dealer, log in logs.items():
        ceremony.record(dealer, log)
    result = observe(ceremony)                       # dkg.md §10
    return result.output if result.ok else S.output  # a failed ceremony carries the input output forward
```

Log collection and selection are [dkg.md §9](commonware/dkg.md#9-log-collection-and-selection) and `observe` is [dkg.md §10](commonware/dkg.md#10-computing-the-output). A validator that is a player computes its share as in [dkg.md §12](commonware/dkg.md#12-player-share-derivation) on the same logs. That gives the same output as `observe`. If its local player state cannot produce a share, it continues as an observer and has no share in `E+1`. On failure, the previous output and the previous share (if any) carry forward.

Implementation note: an implementation MAY take logs from finalized blocks first (the earliest finalized log per dealer), then walks the notarized blocks from `P` down to the latest finalized block for dealers that have no finalized log yet. Because the finalized blocks are ancestors of `P`, this equals the rule above.

### 11.2 Active players

```python
def active_players(vc) -> ordered_set:
    keys = set()
    for v in vc.getActiveValidators():               # contract order
        pk = ed25519_decode(v.publicKey)             # 32 bytes, must decompress
        ingress = parse_socket_addr(v.ingress)       # SocketAddr grammar, see below
        egress  = parse_ip_addr(v.egress)            # IpAddr grammar, see below
        if pk is None or ingress is None or egress is None:
            continue                                 # an entry that does not decode is skipped
        keys.add(pk)                                 # duplicate keys collapse to one
    return sorted(keys)                              # ascending by the 32 key bytes
```

`ed25519_decode` is the public key decoding of [cryptography.md §3.2](commonware/cryptography.md#32-public-key-decoding). `parse_socket_addr` and `parse_ip_addr` accept exactly the `SocketAddr` and `IpAddr` grammars of [precompiles/validator-config-and-zones.md §0.3](precompiles/validator-config-and-zones.md#03-endpoint-text-grammar), including an IPv6 scope id in `SocketAddr`, and fail on any other string. `getActiveValidators()` returns, in `active_indices` order, the records that are active at the post-state of `P`: added at a height `< last(E)` and not deactivated. This matches TIP-1017's player selection with `boundary(E) = last(E)`. The resulting set MUST NOT be empty, because the encoding requires at least one next player.

> **Resolved conflict C-CONS-02**: TIP-1017 says the consensus layer reads ValidatorConfig V1 until ValidatorConfigV2 is initialized, but the implementation always reads ValidatorConfigV2. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-cons-02).

The contract-side definition of these reads is in precompiles/validator-config-and-zones.md ("Consumption by consensus"); the two descriptions are the same rule. For every boundary whose parent post-state has ValidatorConfigV2 initialized, the rule above applies. Earlier mainnet boundary outcomes were produced by earlier releases and are accepted through their finalization certificates. No node recomputes historical boundary outcomes.

## 12. Validator proposal procedure

When Simplex asks the leader `ℓ` (this node) to propose in round `(E, v)` with parent `(pv, pd)`:

1. If this node already holds a verified block for round `(E, v)` (a restart after broadcasting), it MUST NOT propose ([simplex.md §10.1](commonware/simplex.md#101-proposectx)). The view times out instead.
2. Obtain the parent block `P = block(pd)`. If `P.number == last(E)`, re-propose `pd` (§5.3) and stop.
3. Choose `extra_data`:
   - If `P.number + 1 == last(E)` (building the boundary block): `extra_data = encode(boundary_outcome(P))` (§11), computed only after `P` has been executed and is VALID, because §11.2 reads `P`'s post-state.
   - Otherwise: this node's own finalized `SignedDealerLog` for epoch `E` (§9.4 step 5) if it has one that is not yet in a finalized block, else empty.
4. Timestamp: `t_ms = now_ms()`. If `t_ms ≤ P.timestamp_ms`, set `t_ms = P.timestamp_ms + 1`. Then `header.timestamp = t_ms // 1000` and `header.timestamp_millis_part = t_ms % 1000`. Here `timestamp_ms = timestamp * 1000 + timestamp_millis_part`.
5. `consensus_context = {epoch: E, view: v, parent_view: pv, proposer: ℓ}` (From T4; §5.1).
6. Build the block on `P` with payload attributes `timestamp`, `timestamp_millis_part`, `extra_data`, `consensus_context`, `proposer_public_key = ℓ`, `suggested_fee_recipient = 0x00…00`, `prev_randao = 0x00…00`, `withdrawals = []` and `parent_beacon_block_root = 0x00…00`. The builder SHOULD set the beneficiary to the fee recipient that ValidatorConfigV2 records for `proposer_public_key` when that is non-zero. Before T14 the beneficiary is not otherwise validated. Execution-layer validity of these fields is in 05-block-execution.md.
7. Broadcast the block (08-p2p-and-sync.md) and return its hash as the proposal payload.

Pacing is local policy and not normative. Tempo's validators target 550 ms between header timestamps, keeps a network reservation of at least 50 ms, and holds the finished proposal until its time budget runs out.

> **Resolved conflict C-CONS-03**: the docs say blocks come about every 600 ms from a 500 ms builder loop, but the implementation uses an adaptive estimator targeting 550 ms with a 50 ms network budget. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-cons-03).

## 13. Validator verification procedure

For a proposal `(E, v, pv, pd, D)` with leader `ℓ`, a validator runs these checks in order. Each step ends in one of three ways: **continue**, **reject** (the validator answers "invalid" and will never notarize this proposal), or **abstain** (no verdict and no notarize vote; the view ends by timeout or by others' certificates). A reject ends verification with `false`, which makes Simplex nullify the view early while its skip budget lasts ([simplex.md §8.5](commonware/simplex.md#85-receiving-a-proposal), [§8.8](commonware/simplex.md#88-timeouts-and-nullify)). Steps 1–4 are the checks of [simplex.md §10.2](commonware/simplex.md#102-verifyctx-d). A reject or abstain from one validator does not make the block invalid for others.

| # | Check | On failure |
|---|---|---|
| 1 | Obtain block `B` with `hash(B) = D`. It MUST decode as in §5.1 (body matches header, no `block_access_list_hash`). | an undecodable block is discarded; if no block is obtained, abstain |
| 2 | `epoch_of(B.number) == E` | reject |
| 3 | If `D == pd` (re-proposal): accept iff `B.number == last(E)`, and skip steps 4–10 | reject if not at `last(E)` |
| 4 | Obtain parent `P = block(pd)` and require `B.parent_hash == hash(P) == pd` and `B.number == P.number + 1` | parent unavailable: the node keeps waiting for it; if the fetch is abandoned, the verification request closes without an answer, which Simplex treats as an ignored proposal and nullifies early like a reject; mismatch: reject |
| 5 | From T4 (by `B.timestamp`): `B.consensus_context` is present and equals `{E, v, pv, ℓ}`. Presence is also a header-validity rule every node checks (02-encoding.md §2.5) | reject |
| 6 | If `is_boundary(B.number)`: `B.extra_data` decodes as an `OnchainDkgOutcome` (§10.2) | reject |
| 7 | Else, if `B.extra_data` is not empty: if the local DKG state is not at epoch `E`, abstain. Otherwise it MUST decode and check as a `SignedDealerLog` and its dealer MUST equal `ℓ` (§10.1) | abstain / reject |
| 8 | Execute `B` on `P` with the full execution-layer rules (05-block-execution.md, including the header rules: `timestamp_ms > P.timestamp_ms`, `timestamp_millis_part < 1000`, `len(extra_data) ≤ 10240`), by the *verification probe* below | `INVALID`: reject; no verdict: abstain |
| 9 | Clock gate: wait until local time `≥ B.timestamp_ms`. This never rejects; it only delays the vote. | — |
| 10 | If boundary: compute `boundary_outcome(P)` (§11) and require equality with the decoded outcome of step 6, field by field (`epoch`, `output` including summary, polynomial, dealers, players and revealed, `next_players`, `is_next_full_dkg`) | cannot compute (logs or state unavailable): abstain; differs: reject |
| 11 | Accept: the validator sends its notarize vote. | — |

**Verification probe (step 8).** The validator submits `B` to its execution layer with `engine_newPayload` (Engine API semantics, 08-p2p-and-sync.md §0) and reads the status:

- `VALID`: step 8 passes.
- `INVALID`: reject. This covers an invalid ancestor too, because the execution layer answers `INVALID` for every descendant of a block it found invalid.
- `SYNCING` (the execution layer lacks an ancestor): the validator walks down `B`'s ancestry one block at a time. It obtains the missing parent from its execution layer or its consensus stores, or else fetches it from peers by hash (`Block(d)`, 08-p2p-and-sync.md §3.3.5), and submits that block with `engine_newPayload`. A `SYNCING` answer moves the walk to the next parent; a `VALID` answer makes it submit `B` again for the verdict. The walk never goes below the latest finalized block. When the missing block is the finalized tip or below it, the validator waits until finalized-block delivery has executed it, then submits `B` again.
- `ACCEPTED` (stored without execution): abstain.

The validator also abstains when finality passes `B`'s height before a verdict, when a newly finalized block conflicts with `B`'s ancestry, when a later request for the same round replaces this one, or when the block fetch is abandoned. None of these is a reject. An engine call that fails outright, without a status, is fatal.

There is no upper bound on how far a timestamp may be ahead of local time. A block from the future only delays the votes of validators whose clocks are behind (step 9).

After finalization (Simplex finalize votes), a validator delivers finalized blocks to its execution layer in height order and acknowledges them only once they are durably persisted (08-p2p-and-sync.md).

## 14. Epoch transition (validator)

For a validator in epoch `E`, the transition happens when the finalized block `last(E)` is processed, in height order with every other finalized block. It does not wait for a block of epoch `E+1`. The steps run in this order:

1. Epoch `E`'s instance finalizes the boundary block `last(E)`, possibly as a re-proposal in a later view. Marshal delivers it once every lower height is processed.
2. The DKG component reads `outcome(E+1)` from the `extra_data` of `last(E)`. It sets the share to the one this node concluded for that parent, or none if its local output differs from `outcome(E+1).output` or it was not a player. It durably persists the new state `S(E+1)` (§9.1) before step 3.
3. **Exit `E`.** The validator stops epoch `E`'s Simplex instance and ceremony. This deregisters `E`'s subchannels on the vote, certificate, resolver and DKG channels (08-p2p-and-sync.md §3.2). It deletes the verification key of epoch `E−2`, if any, and keeps those of `E−1` and `E`.
4. **Enter `E+1`.** It installs epoch `E+1`'s key and starts its instance (§5.3) with `floor = hash(last(E))`, participants `outcome(E+1).output.players`, the elector version from `header(last(E)).timestamp`, and its share if it has one. This registers `E+1`'s vote, certificate and resolver subchannels. It then starts the ceremony of epoch `E+1` with `info(E+1)`, which registers `E+1`'s DKG subchannel.

Consequences:

- From step 3 on, the validator sends no vote, certificate or resolver message for `E` and answers none. Certificates, resolver messages and DKG messages for `E` are dropped, and votes for `E` go to the vote backup queue, which ignores them (08-p2p-and-sync.md §3.2). Through marshal backfill, it still accepts finalizations and notarizations of `E−1` and `E` from stragglers, such as a finalization of a later re-proposal of `last(E)`, and still serves its own stored ones.
- Votes for `E+1` that arrive before step 4 go to the backup queue. There they trigger a fetch of the finalization of `last(E)` (if it isn't stored yet) and are then discarded. They are never delivered to `E+1`'s instance.
- After step 4 the validator holds three keys: `E−1`, `E` and `E+1`.

A validator that sees votes for an epoch later than its own SHOULD fetch the finalization of its current epoch's boundary block and catch up one epoch at a time (08-p2p-and-sync.md). Simplex's per-epoch vote journal MUST be persisted ([simplex.md §8.13](commonware/simplex.md#813-persistence)), so that a validator never signs two conflicting votes in one round across restarts.

## 15. Fork-dependent consensus behaviour

| Fork | Keyed on | Behaviour |
|---|---|---|
| T0 (mainnet genesis) | — | Everything in this chapter except the rows below: elector V0, reveal V0, no header `consensus_context`, immediate verification. |
| T2 | block timestamp (EL) | The ValidatorConfigV2 precompile appears (precompiles/validator-config-and-zones.md). The consensus layer reads next players from it once it is initialized (§11.2, C-CONS-02). |
| T4 | block timestamp | Header `consensus_context` absent before T4 and present on every block from T4, a header-validity rule every node checks. Voters also check its contents (§5.1, C-CONS-01). |
| T8 | block timestamp (EL) | Block execution decodes the boundary `OnchainDkgOutcome` and writes `(outcome.epoch, outcome.output.players)` to CurrentCommittee. An undecodable boundary outcome makes the block invalid (05-block-execution.md). |
| T12 | `boundary_timestamp(E)` | Leader election version V1 (§6) and DKG Reveal V1 (§9.2) for epoch `E` and its ceremony. |
| T14 (out of scope) | `boundary_timestamp(E)` | Deferred verification by default, and beneficiary validation. Not part of T13. |

No other fork from T0 to T13 changes consensus-layer behaviour.

## 16. Versions of the commonware documentation

The commonware chapters listed in §2 restate commonware version 2026.9.0.

> **Resolved conflict C-CONS-04**: the consensus docs page links version 0.0.65 of commonware's consensus crate, but the implementation and this chapter use commonware 2026.9.0. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-cons-04).

## 17. Open items

> **Note (historical, informative)**: Mainnet outcomes up to and including `outcome(624)` (block 13,478,399 = `last(623)`) were produced by earlier releases from ValidatorConfig V1 (`0xCCCCCCCC00000000000000000000000000000000`). From `outcome(625)` (block 13,499,999 = `last(624)`) on, §11.2 applies. The switch is per boundary: earlier releases used V2 for the boundary with parent `P` iff `can_use_v2(P)`.
```python
def can_use_v2(P):
    return (is_t2_active(P.timestamp)
            and ValidatorConfigV2.isInitialized()
            and ValidatorConfigV2.getInitializedAtHeight() <= P.number)

def v1_active_players(h):                        # V1 at the post-state of block h
    by_key = {}
    for v in ValidatorConfigV1.getValidators():  # contract order
        pk = ed25519_decode(v.publicKey)
        inbound = parse_socket_addr(v.inboundAddress)
        outbound = parse_socket_addr(v.outboundAddress)
        if pk is None or inbound is None or outbound is None:
            continue
        by_key[pk] = v                           # a later duplicate replaces an earlier one
    return sorted(k for k, v in by_key.items() if v.active)

def boundary_outcome_v1(P):                      # when not can_use_v2(P)
    E = epoch_of(P.number)
    prev = 0 if E == 0 else last(E - 1)
    return OnchainDkgOutcome(
        epoch = E + 1,
        output = ceremony_output(E, P),
        next_players = v1_active_players(prev),  # one epoch behind
        is_next_full_dkg = (ValidatorConfigV1.getNextFullDkgCeremony() at the post-state of P == E + 1),
    )
```
> On mainnet, T2 activates at block 12,290,227 (timestamp 1,774,965,600). ValidatorConfigV2 records `initializedAtHeight = 13,486,706`. No node recomputes these outcomes: followers and validators accept them through their finalization certificates.

> **Note (informative)**: Through epoch 2201 (block 47,548,251), mainnet's network identity has rotated once.
> - `outcome(2041)` (block 44,085,599 = `last(2040)`) has `is_next_full_dkg = true`.
> - The ceremony of epoch 2041 was a full DKG. `outcome(2042)` (block 44,107,199 = `last(2041)`) carries the identity `0x8627d337…a182` of the checkpoint (§3).
> - Epochs 0 to 2041 use the genesis identity `0xa217bb85001d4dcf8e5c50136f77af88cb2cab1857279b91c6240f41cca95c4f43f6dcab3e0dfb87dafb3ecbeb6251e90a5df2e6c47432482821cd8b84665ee4642589d2d9628a92b03e2bbfb00e006d038cd98def76d2a41b7c228c05f5a193`.
> - Every other boundary outcome has `is_next_full_dkg = false`. Later rotations can be found by decoding every boundary block's outcome.
