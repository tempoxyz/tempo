# 07 — Consensus

This chapter specifies Tempo's consensus layer: epochs, how blocks map onto Simplex proposals, the Simplex instantiation and its signing domains, leader election, finalization certificates and how followers verify them, the chain of trust in the network identity, the per-epoch DKG, the DKG artifacts carried in header `extra_data`, and the procedures validators follow to propose and to vote.

Transport, channel numbering, message framing on the wire, peer sets, backfill, the `tempo/1` RLPx subprotocol, follower block sources and persistence formats are in [08-p2p-and-sync.md](08-p2p-and-sync.md). Header field encodings (including `consensus_context`) are in [02-encoding.md](02-encoding.md). Execution-layer header and block checks (timestamps, the 10 KiB `extra_data` cap, the T8 committee system call) are in [05-block-execution.md](05-block-execution.md). The ValidatorConfigV2 and CurrentCommittee contracts are in [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md).

## 1. Roles and what each must implement

A **follower** trusts a block once it holds a valid finalization certificate for that block or a descendant. A follower MUST implement §2–§4, §7, §8 and the decoding of §10. It does not run Simplex, the DKG, or the proposal and voting rules.

A **validator** participates in Simplex and in the DKG. It MUST implement this whole chapter.

A rule marked *(validator voting rule)* decides whether an honest validator votes for a proposal. It is not checked when a finalized block is replayed. A finalized block that breaks such a rule is still part of the chain: the certificate is what makes it final.

## 2. Normative dependencies

The following components are normative by reference, pinned to **commonware 2026.9.0** (tag `v2026.9.0` of `commonwarexyz/monorepo`, commit `d476a2361ce6840d2b9d0aa6fb30a924429046d4`). A conforming client MUST reproduce their wire formats and algorithms bit for bit.

| Component | Crate and item |
|---|---|
| Codec (varint `UInt`, `bool`, fixed arrays, `Vec` with length prefix, `RangeCfg`) | `commonware-codec` |
| Ordered sets (sorted and deduplicated, decode rejects unsorted or duplicate items) | `commonware_utils::ordered::Set` |
| `union` (plain concatenation), `union_unique` (`varint(len(ns)) ‖ ns ‖ msg`), `modulo` (big-endian bytes mod n) | `commonware_utils` |
| Fault model: `f = (n − 1) / 3` (integer division), quorum `q = n − f` | `commonware_utils::N3f1` |
| Epoch arithmetic and phases | `commonware_consensus::types::{Epoch, View, Round, Height, FixedEpocher, EpochInfo, EpochPhase}` |
| Simplex BFT (votes, certificates, view changes, locking, nullification, skip) | `commonware_consensus::simplex` (`Engine`, `config::Config`, `types::{Proposal, Context, Vote, Certificate, Notarization, Nullification, Finalization}`) |
| Threshold VRF signing scheme | `commonware_consensus::simplex::scheme::bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>` |
| Leader election | `commonware_consensus::simplex::elector::{Random<Sha256>, RandomVersion}` |
| Marshal wrapper (epoch membership, parent linkage, boundary re-proposal) | `commonware_consensus::marshal::standard::Inline` |
| BLS12-381 MinSig (signatures in G1, 48 bytes compressed; public keys in G2, 96 bytes compressed), hash-to-curve DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` | `commonware_cryptography::bls12381::primitives::{variant::MinSig, ops}` |
| DKG and resharing | `commonware_cryptography::bls12381::dkg::feldman_desmedt::{Info, Mode, Reveal, Dealer, Player, DealerPubMsg, DealerPrivMsg, PlayerAck, DealerLog, SignedDealerLog, Logs, Output, observe}` |
| Public polynomial and share | `commonware_cryptography::bls12381::primitives::{sharing::Sharing, group::Share}` |
| Ed25519 (32-byte public keys, `Ord` = lexicographic order of the 32 bytes; ZIP-215 verification) | `commonware_cryptography::ed25519` |

Every BLS signature in this chapter is `ops::sign_message::<MinSig>(sk, ns, msg)`: the G1 hash of `union_unique(ns, msg)` under the DST above, multiplied by the secret scalar. Threshold partials use `ops::threshold::sign_message` with the same message.

Reference implementation: Cargo.toml (commonware-* = "2026.9.0").

## 3. Constants

| Name | Value | Notes |
|---|---|---|
| `NAMESPACE` | `b"TEMPO"` | Simplex scheme namespace and DKG `Info` namespace |
| Simplex vote namespaces | `b"TEMPO_NOTARIZE"`, `b"TEMPO_NULLIFY"`, `b"TEMPO_FINALIZE"`, `b"TEMPO_SEED"` | `union(NAMESPACE, suffix)` (§5.2) |
| P2P handshake namespace | `union_unique(b"TEMPO", b"_P2P")` | Used only by the transport; see 08-p2p-and-sync.md |
| `L` (epoch length) | 21,600 blocks on mainnet (4217) and on moderato (42431) | Genesis `config.epochLength`; see 01-chain-and-forks.md |
| Fault model | `N3f1` | Simplex quorum and DKG thresholds |
| `MAX_VALIDATORS` | 65,535 (`u16::MAX`) | Decode bound for player sets in `OnchainDkgOutcome` |
| `TEMPO_MAXIMUM_EXTRA_DATA_SIZE` | 10,240 bytes | EL cap on header `extra_data` (05-block-execution.md); every DKG artifact MUST fit |
| Mainnet network identity checkpoint | `from_epoch = 2042`, identity `0x8627d33753b0d90a8eae75363d6b393ab9204076545b3af6caf831903e4bedde4374f1106551b481fb5ea35e59d51c92165c963881c718216e3e4570a307c08885af55c274f19488f709afe021ca3d9e567138ab097860d9146e895407bea182` | `mainnet-network-identity.json` (§8.4) |
| Moderato network identity checkpoint | `from_epoch = 1747`, identity `0x967ae1a6d3ddbe5cb0fe5e6fc58e74249787b4a277619b549fed6609d04660540dd2449cd7174def35e40f544e5ad72d15d064191a205ed6e0c49619c68f975108b614d0d51def9a8416a10a07c4193bea0cbbc4252ec1b33f21095a5d7aa590` | `testnet-network-identity.json` |

On both networks the genesis timestamp is 0 and the genesis header `extra_data` is a 716-byte `OnchainDkgOutcome` for epoch 0 (§10.3).

Reference implementation: crates/consensus/src/config.rs, crates/dkg-onchain-artifacts/src/lib.rs, crates/evm/src/consensus/mod.rs, crates/chainspec/src/genesis/presto.json, mainnet-network-identity.json, testnet-network-identity.json.

## 4. Epochs

### 4.1 Mapping heights to epochs

Epochs have a fixed length `L` (`FixedEpocher`). With integer division:

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

The phase of a height within its epoch (`EpochInfo::phase`):

| Phase | Condition | Mainnet heights in epoch `e` (`L = 21600`) |
|---|---|---|
| `Early` | `relative(h) < L // 2` | `first(e) … first(e) + 10799` |
| `Midpoint` | `relative(h) == L // 2` | `first(e) + 10800` |
| `Late` | `relative(h) > L // 2` | `first(e) + 10801 … last(e)` |

Phases drive DKG timing (§9.4). They do not affect block validity.

Reference implementation: commonware consensus/src/types.rs (FixedEpocher, EpochInfo::phase); crates/consensus/src/consensus/engine.rs (FixedEpocher::new(epoch_length)); crates/consensus/src/dkg/manager/actor/mod.rs (latest_boundary_at_or_before).

## 5. Simplex instantiation

### 5.1 Block ↔ proposal mapping

- The Simplex **digest** of a block is its 32-byte block hash `keccak256(rlp(TempoHeader))` (02-encoding.md). The digest is the commonware `Digest` codec: 32 raw bytes.
- A **Proposal** is `{round: Round(epoch, view), parent: View, payload: Digest}`, encoded as `varint(epoch) ‖ varint(view) ‖ varint(parent_view) ‖ payload[32]`.
- A block's **parent digest** is `header.parent_hash` and its **height** is `header.number`.
- The Simplex **Context** of a proposal is `{round: (epoch, view), leader: ed25519 public key, parent: (parent_view, parent_digest)}`.
- On the consensus network a block travels as the raw RLP of the sealed execution block (header and body), with no other framing. A receiver MUST reject an encoding that does not decode, whose body does not match the header commitments (transactions root, withdrawals root and the other body checks of 05-block-execution.md), or whose header contains a `block_access_list_hash`.

#### Header consensus context

From T4, every block after genesis carries `header.consensus_context = {epoch, view, parent_view, proposer}` (TIP-1031; encoding in 02-encoding.md), and this equals the Context the block was proposed under: `epoch` and `view` of the proposal's round, `parent_view` of its parent, and `proposer` = the round's leader as 32 raw Ed25519 bytes. Blocks before T4 have no `consensus_context`. The genesis block has none.

A validator voting on a proposal MUST require that the context is present and equal to the engine's Context (§13). The execution layer does not check whether the field is present.

> **Open conflict C-CONS-01**: TIP-1031 requires the context to be absent before T4 and the check to depend on activation, but the implementation has no T4 gate: it always builds and requires a context. See [conflicts](conflicts.md#c-cons-01).

Every mainnet block a validator votes on under T13 rules has its timestamp after T4, so the rule above (present and equal) applies to them. A block whose header has no context maps to a Context that can never match a real round. The reference implementation uses leader = the Ed25519 public key of the seed-0 private key, round `(0, 0)` and parent `(0, 0x00…00)`, so its verification always fails.

Reference implementation: crates/consensus/src/consensus/digest.rs, crates/consensus/src/consensus/block.rs, crates/primitives/src/header.rs, commonware consensus/src/simplex/types.rs (Proposal).

### 5.2 Signing scheme and signing domains

Each epoch's Simplex instance uses `bls12381_threshold::vrf::Scheme<ed25519::PublicKey, MinSig>` with namespace `NAMESPACE = b"TEMPO"`:

- **Participants** of epoch `E` are `outcome(E).output.players`, the ordered set of Ed25519 keys from the outcome that opened `E` (§8.2). A participant's index is its position in that set.
- **Group public key** (network identity) of epoch `E` is `outcome(E).output.public.public()`, the constant term of the public polynomial (96-byte G2).
- A validator with a share for epoch `E` is a **signer**; any other node runs the epoch as a **verifier**.

Each vote carries two threshold partial signatures made with the signer's share: a *vote signature* and a *seed signature*. Each certificate carries the two recovered threshold signatures. The signed messages (each hashed as `union_unique(ns, msg)`, §2) are:

| Subject | Vote namespace `ns` | Vote message | Seed namespace | Seed message |
|---|---|---|---|---|
| Notarize / Notarization | `b"TEMPO_NOTARIZE"` | `encode(Proposal)` | `b"TEMPO_SEED"` | `encode(proposal.round)` |
| Nullify / Nullification | `b"TEMPO_NULLIFY"` | `encode(Round)` | `b"TEMPO_SEED"` | `encode(Round)` |
| Finalize / Finalization | `b"TEMPO_FINALIZE"` | `encode(Proposal)` | `b"TEMPO_SEED"` | `encode(proposal.round)` |

`encode(Round)` is `varint(epoch) ‖ varint(view)`. A certificate is valid iff both recovered signatures verify against the epoch's group public key; the reference implementation batch-verifies the two (`batch::verify_same_signer`). The threshold is the `N3f1` quorum `q = n − f` of the epoch's `n` participants, and so is the number of votes needed for each certificate.

Ed25519 keys sign no Simplex votes. They authenticate p2p connections (08-p2p-and-sync.md), DKG acknowledgements and dealer logs (§9), and ValidatorConfigV2 operations.

Reference implementation: crates/consensus/src/epoch/manager/actor.rs (enter), commonware consensus/src/simplex/scheme/mod.rs (namespaces), consensus/src/simplex/scheme/bls12381_threshold/vrf.rs (sign, verify_certificate).

### 5.3 Epoch-scoped instances

Each epoch `E` runs its own Simplex instance with this configuration:

| Parameter | Value | Interop-relevant |
|---|---|---|
| `epoch` | `E` | yes |
| `floor` | `Floor::Genesis(hash(preceding_boundary_height(E)))`: the hash of block `last(E−1)`, or the genesis hash for `E = 0` | yes |
| `scheme` | §5.2 with the participants and polynomial of `outcome(E)` | yes |
| `elector` | `elector::Random::<Sha256>::new(version(E))` (§6) | yes |
| `leader_timeout` | 1,200 ms | no (liveness) |
| `certification_timeout` | 2 s | no |
| `timeout_retry` (nullify rebroadcast) | 10 s | no |
| `fetch_timeout` | 2 s | no |
| `view_retention` (activity timeout) | 256 views | no |
| `skip` | `SkipPolicy::Enabled { timeout: 11.2 s, budget: SkipBudget::Participants }` | no |
| `forward` | `ForwardPolicy::Disabled` | no |
| `track_historical_votes` | true | no |

Parameters marked "no" are local policy. Validators SHOULD use the listed values, because very different timeouts harm liveness, but they do not change which blocks are valid. The engine requires `certification_timeout > leader_timeout`, and `skip.timeout` greater than both `certification_timeout` and `timeout_retry`.

Within an epoch, views start at 1. The floor sits at view 0. The first block of epoch `E` therefore has height `first(E)`, `parent_hash = hash(last(E−1))` and `consensus_context.parent_view = 0`. Epoch 0's first block is height 1, with genesis as parent.

Block-to-epoch membership *(validator voting rule)*: a proposal in round `(E, v)` is acceptable only if its block's height is in epoch `E`. Its parent must be the block named by the context's parent digest, with height exactly one less (§13).

**Boundary re-proposal.** When the parent chosen for a proposal in epoch `E` is the boundary block `last(E)`, the leader MUST NOT build a new block. It re-proposes the boundary block: the proposal's payload equals `context.parent.1`, the parent digest. A proposal whose payload equals its parent digest is valid iff the block it names has height `last(E)`. The application does not verify it again. So the boundary block can be notarized and finalized in a later view than the one recorded in its header `consensus_context`, and no block above `last(E)` is ever proposed in epoch `E`.

**Certification (Before T14).** The verification mode is *immediate*: the application's verify (§13) completes before the node sends its notarize vote, and certify returns once the block is available locally. (Deferred verification, the default from T14, is out of scope. TIP-1031 lets a validator keep synchronous verification in any case.)

Reference implementation: crates/consensus/src/epoch/manager/actor.rs (enter), crates/consensus/src/args.rs (defaults, validate_simplex_timing, VerificationMode), crates/consensus/src/consensus/application/mod.rs, commonware consensus/src/marshal/standard/{inline.rs, validation.rs}.

## 6. Leader election

The leader of round `(E, v)` is participant `players[idx]` of epoch `E` (§5.2), where `n = len(players)`:

```python
def leader_index(E: int, v: int, n: int, seed_sig: bytes | None, version: str) -> int:
    # seed_sig: the 48-byte compressed G1 seed signature of round (E, v-1), taken from the
    # certificate (notarization, nullification or finalization) for view v-1 that let the node
    # enter view v. It is None only for v == 1.
    if seed_sig is None:
        assert v == 1
        return (E + v) % n
    if version == "V0":
        return int.from_bytes(seed_sig, "big") % n
    else:  # "V1"
        return int.from_bytes(sha256(seed_sig), "big") % n
```

The seed signature of a round is the same whichever certificate kind carries it, so every honest node chooses the same leader.

Version selection:

- **Before T12** (T12 not active at `boundary_timestamp(E)`): `RandomVersion::V0`.
- **From T12** (T12 active at `boundary_timestamp(E)`): `RandomVersion::V1` (TIP-1116 §5).

The version is fixed for the whole epoch. The first epoch of mainnet that uses V1 is the first `E` whose block `last(E−1)` has `timestamp ≥ 1791900000`.

Reference implementation: crates/consensus/src/epoch/manager/actor.rs (elector selection), commonware consensus/src/simplex/elector.rs (Random::select_leader), commonware utils/src/lib.rs (modulo).

## 7. Certificates and follower verification

### 7.1 Encodings

Encoded with the commonware codec:

```text
Round          = varint(epoch:u64) ‖ varint(view:u64)
Proposal       = Round ‖ varint(parent_view:u64) ‖ payload[32]
VrfCertificate = vote_signature[48] ‖ seed_signature[48]        # compressed G1 points
Notarization   = Proposal ‖ VrfCertificate
Finalization   = Proposal ‖ VrfCertificate
Nullification  = Round ‖ VrfCertificate
```

A follower decoding a `Finalization` MUST consume the input exactly and MUST reject a G1 point that does not decode (invalid encoding, not on the curve, or not in the subgroup), as the commonware decoder does. The framings that carry certificates (the `tempo/1` `NewFinalization` frame, RPC responses, the marshal resolver) are in 08-p2p-and-sync.md.

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

A valid finalization of `B` finalizes `B` and, through the `parent_hash` chain, every ancestor of `B`. A follower MAY skip certificates for intermediate blocks. It MUST take the ancestors' bodies by following `parent_hash` from `B` down to its last finalized block, checking that each block hashes to the digest its child names. Two valid finalizations for different blocks at the same height cannot exist unless more than `f` participants of the epoch are faulty. A follower that sees them SHOULD stop rather than choose one.

Validators verify finalizations, notarizations and nullifications received over the network with the same keys and namespaces. A validator MAY accept a finalization or notarization for any epoch whose key it holds, including straggler certificates for an epoch it already left (the reference implementation keeps the last two epochs' schemes).

Reference implementation: crates/consensus/src/finalization_verifier/mod.rs, crates/consensus/src/follow/driver/actor/mod.rs (process_event, process_certificate).

## 8. Trust chain and network identity

### 8.1 Root of trust

When syncing from genesis, the root of trust is `outcome(0) = OnchainDkgOutcome.read(genesis.extra_data)`. Its `epoch` MUST be 0, and its group key verifies epoch 0's certificates. The genesis hash itself comes from the chain specification (04-state-and-genesis.md).

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

A client MAY ship a checkpoint `NetworkIdentity = {from_epoch: u64, identity: G2}`. Its JSON form is exactly `{"from_epoch": <u64>, "identity": "0x<192 hex chars>"}` (no other fields), where `identity` is the 96-byte compressed G2 group key, which MUST decode as a valid G2 point. The mainnet and moderato values are in §3. Each one is the identity produced by the network's most recent full DKG at the time of the release, and from_epoch is the epoch whose certificates it first verifies.

```python
def trusted_key(E: int) -> G2:
    if E in keys:
        return keys[E]
    if E >= checkpoint.from_epoch:
        return checkpoint.identity      # valid until the next rotation; on failure, sync boundaries (§8.2)
    raise IdentityUnavailable(E)        # sync boundary blocks from an earlier trusted epoch
```

At startup a client MUST call `install(checkpoint.from_epoch, checkpoint.identity)`. A key derived from the chain for that epoch must then agree with the checkpoint, or the client stops. For epochs above `from_epoch` the checkpoint is only a fallback: when an on-chain outcome for such an epoch carries a different key, the chain-derived key is installed for that epoch, and the client SHOULD warn that its checkpoint is outdated.

A client that persists the latest identity it derived from the chain (as `{from_epoch, identity}`) chooses, at startup:

```python
trusted = configured_checkpoint
if persisted is not None:
    if persisted.from_epoch == configured_checkpoint.from_epoch:
        require(persisted.identity == configured_checkpoint.identity)   # else fatal
    if persisted.from_epoch > configured_checkpoint.from_epoch:
        trusted = persisted
```

and then checks its locally stored finalized tip, if any. A tip whose certificate epoch is `≥ trusted.from_epoch` MUST verify against `trusted.identity`, which is then installed for that epoch. A tip from an earlier epoch is accepted as local history without verification. Only genesis (height 0) may have no certificate. Finally `install(trusted.from_epoch, trusted.identity)`.

> Informative: the mainnet checkpoint (`from_epoch = 2042`) means a full DKG ran during epoch 2041. Its identity differs from the genesis identity.

Reference implementation: crates/chainspec/src/network_identity.rs, crates/chainspec/src/spec.rs (with_network_identity), crates/consensus/src/startup.rs (verify_finalized_tip), crates/consensus/src/epoch/scheme_provider.rs (register), crates/consensus/src/follow/driver/actor/mod.rs (observe_boundary_identity, process_update).

## 9. Distributed key generation

Each epoch runs one Feldman–Desmedt ceremony (commonware `feldman_desmedt`, fault model `N3f1`). The ceremony run during epoch `E` produces the output that `outcome(E+1)` carries.

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

`Reveal::V0` applies before T12 and `Reveal::V1` from T12 (TIP-1116 §4), keyed on the ceremony's starting boundary exactly like the elector (§6). The reveal version enters the round's transcript summary, so acks, dealer logs and outputs from rounds of different versions are incompatible. In a resharing round each dealer deals from its current share. In a full round (`previous = None`) dealers deal fresh secrets. A dealer without a share in a resharing round does not deal.

### 9.3 DKG messages

DKG messages travel on the DKG channel, multiplexed by `u64` epoch (08-p2p-and-sync.md). A message's payload is:

```text
DkgMessage = 0x00 ‖ DealerPubMsg<MinSig> ‖ DealerPrivMsg      # dealer → one player
           | 0x01 ‖ PlayerAck<ed25519::PublicKey>             # player → dealer
```

`DealerPubMsg` is read with `cfg = len(S.players)`. The whole payload MUST decode exactly, and any other tag is invalid. A node SHOULD block a peer that sends an undecodable message or an invalid dealing.

### 9.4 Timing (validator behaviour)

The DKG is driven by **finalized** blocks of epoch `E`, in height order:

1. **Early phase.** For each finalized block in `Early`, a dealer (re)sends `Dealer(pub, priv_p)` to every player `p` that has not yet acked. A dealer that is also a player processes its own dealing locally.
2. **Players.** When a player receives a valid dealing from a dealer for the first time, it MUST persist the dealing before it returns `Ack`. It MUST return the same ack for any later copy, and MUST NOT ever ack a different dealing from the same dealer in the same round.
3. **Acks.** A dealer accepts the first ack from each player, and persists it, until it finalizes. If that first ack is invalid, the dealer stops retrying that player.
4. **Midpoint and later.** On the first finalized block in `Midpoint` or `Late` (or at startup when the latest finalized block of the epoch is past `Early`), a dealer finalizes its `SignedDealerLog`: its commitment plus, for each player, the ack or the revealed share (`Dealer::finalize::<N3f1>`).
5. **Posting.** Whenever the dealer is the leader of a round of epoch `E` and proposes a regular block, it includes its own finalized log as `extra_data` (§10.1). It does this in every such proposal until it observes the log in a finalized block.
6. **Conclusion.** At the boundary, the output is computed from the logs on chain (§11.1).

Nothing in block validity enforces these timings. For example, a log that appears before the midpoint is still valid.

A validator MUST persist, per epoch, the dealings it received and the acks it gave, and MUST persist the new DKG state (epoch, output, share, players, is_full_dkg) before it enters the next epoch. Otherwise it may equivocate after a restart. Storage formats are in 08-p2p-and-sync.md.

### 9.5 Share recovery (informative)

A validator that lost its share MAY rebuild it from finalized history. If it was a player in epoch `E−1`'s ceremony and that ceremony succeeded (`outcome(E).output != outcome(E−1).output`), it runs `Player.finalize` on the first valid log of each selected dealer found in blocks `first(E−1)…last(E−1)−1`, together with any shares those logs reveal to it. The rebuilt output MUST equal `outcome(E).output`. A configured initial share is used only if its public share matches `outcome(E).output.public`.

Reference implementation: crates/consensus/src/dkg/manager/actor/mod.rs (Message, run_dkg_loop, handle_finalized_header, distribute_shares, handle_network_msg, conclude_ceremony, establish_initial_state, maybe_recover_revealed_share), crates/consensus/src/dkg/manager/actor/state.rs (Round::from_state, Dealer, Player).

## 10. On-chain DKG artifacts

All decoding below is **prefix decoding**: the reference implementation reads the artifact from the start of `extra_data` and ignores any trailing bytes. Proposers MUST encode the artifact exactly, with no trailing bytes. Implementations MUST NOT reject an artifact only because trailing bytes follow it, or they would vote differently from the reference implementation.

### 10.1 `SignedDealerLog` in regular blocks

```text
extra_data (regular block) = empty
                           | SignedDealerLog<MinSig, ed25519::PrivateKey>     # read with cfg = len(S(E).players)
SignedDealerLog            = dealer:ed25519::PublicKey[32] ‖ DealerLog<MinSig, ed25519::PublicKey> ‖ sig:ed25519::Signature[64]
DealerLog                  = DealerPubMsg<MinSig> ‖ results                     # per-player ack or reveal (commonware layout)
```

`SignedDealerLog.check(info(E))` verifies the dealer's Ed25519 signature over the log's transcript, which is bound to `info(E)`. It returns `(dealer, log)` or fails.

Inclusion rule *(validator voting rule)*, for a regular block proposed in round `(E, v)` with leader `ℓ`:

1. If `extra_data` is empty, accept.
2. Otherwise `extra_data` MUST decode as a `SignedDealerLog` for epoch `E` and pass `check(info(E))`, and the returned `dealer` MUST equal `ℓ`. Anything else is a reject.
3. If the validator's DKG state is not at epoch `E`, so it cannot check the log, it abstains (§13).

The ceremony itself (§11.1) ignores regular-block `extra_data` that fails to decode or to check, wherever it appears. It also ignores later logs from a dealer whose earlier log is already counted.

### 10.2 `OnchainDkgOutcome` in boundary blocks

```text
OnchainDkgOutcome =
    varint(epoch:u64)                                    # the epoch this outcome opens
  ‖ Output<MinSig, ed25519::PublicKey>                   # read with cfg (max_participants = 65535, ModeVersion::v0())
  ‖ ordered::Set<ed25519::PublicKey> next_players        # varint(len) ‖ 32-byte keys, strictly increasing, 1 ≤ len ≤ 65535
  ‖ bool is_next_full_dkg                                # one byte, 0x00 or 0x01

Output = Summary[32] ‖ Sharing<MinSig> public ‖ ordered::Set dealers (1..=65535)
       ‖ ordered::Set players (1..=65535) ‖ ordered::Set revealed (0..=65535)
```

`Sharing` is the commonware encoding of the public polynomial (mode version, participant total and G2 coefficients). Its constant term is the network identity. `players` is the committee of epoch `epoch`. `dealers` are the dealers whose logs formed the output. `revealed` lists the players whose shares were revealed.

The boundary block `last(E)` MUST carry, as `extra_data`, the encoding of the outcome given by §11 for its parent. `epoch` MUST be `E+1`.

- *(validator voting rule)* A validator rejects a boundary proposal whose `extra_data` does not decode as an `OnchainDkgOutcome`, or whose decoded outcome differs from its own computation (§13).
- **From T8**, block execution also decodes the boundary outcome for the CurrentCommittee system call, and a block that fails this decode is invalid for every node (05-block-execution.md). **Before T8**, block execution does not read `extra_data`.

Every node treats a *finalized* boundary block without a decodable outcome as a fatal inconsistency. Size: the encoding MUST fit within 10,240 bytes. It grows by about 32 bytes per key in each of the three key sets and by 96 bytes per polynomial coefficient (one coefficient per unit of quorum).

### 10.3 Genesis

The genesis header `extra_data` is an `OnchainDkgOutcome` with `epoch = 0`: epoch 0's committee and identity, the players of the ceremony run during epoch 0, and `is_next_full_dkg`. On mainnet and moderato it is 716 bytes: 4 players, polynomial quorum 3, and 4 next players. The genesis `consensus_context` is absent.

Reference implementation: crates/dkg-onchain-artifacts/src/lib.rs, crates/consensus/src/dkg/manager/actor/state.rs (ReducedBlock::from_block_for_round), crates/consensus/src/dkg/manager/actor/mod.rs (read_dealer_log, handle_verify_dealer_log), crates/evm/src/block.rs (apply_current_committee_system_call).

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
    ceremony = Logs[MinSig, PublicKey, N3f1](info(E))
    for dealer, log in logs.items():
        ceremony.record(dealer, log)
    result = observe[N3f1](ceremony)                 # commonware feldman_desmedt::observe
    return result.output if result.ok else S.output  # a failed ceremony carries the input output forward
```

A validator that is a player computes its share with `Player.finalize` on the same logs. That gives the same output as `observe`. If its local player state cannot produce a share, it continues as an observer and has no share in `E+1`. On failure, the previous output and the previous share (if any) carry forward.

Implementation note: the reference implementation takes logs from finalized blocks first (the earliest finalized log per dealer), then walks the notarized blocks from `P` down to the latest finalized block for dealers that have no finalized log yet. Because the finalized blocks are ancestors of `P`, this equals the rule above.

### 11.2 Active players

```python
def active_players(vc) -> ordered_set:
    keys = set()
    for v in vc.getActiveValidators():               # contract order
        pk = ed25519_decode(v.publicKey)             # 32 bytes, must be a valid point
        ingress = parse_socket_addr(v.ingress)       # "<ipv4>:<port>" or "[<ipv6>]:<port>"
        egress  = parse_ip_addr(v.egress)            # "<ipv4>" or "<ipv6>"
        if pk is None or ingress is None or egress is None:
            continue                                 # an entry that does not decode is skipped
        keys.add(pk)                                 # duplicate keys collapse to one
    return sorted(keys)                              # ascending by the 32 key bytes
```

`getActiveValidators()` returns, in `active_indices` order, the records that are active at the post-state of `P`: added at a height `< last(E)` and not deactivated. This matches TIP-1017's player selection with `boundary(E) = last(E)`. The resulting set MUST NOT be empty, because the encoding requires at least one next player.

> **Resolved conflict C-CONS-02**: TIP-1017 says the consensus layer reads ValidatorConfig V1 until ValidatorConfigV2 is initialized, but the implementation always reads ValidatorConfigV2. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](conflicts.md#c-cons-02).

The contract-side definition of these reads is in precompiles/validator-config-and-zones.md ("Consumption by consensus"); the two descriptions are the same rule. For every boundary whose parent post-state has ValidatorConfigV2 initialized, the rule above applies. Earlier mainnet boundary outcomes were produced by earlier releases and are accepted through their finalization certificates. No node recomputes historical boundary outcomes.

Reference implementation: crates/consensus/src/consensus/application/parent_state.rs, crates/consensus/src/validators.rs (read_active_peers, DecodedValidatorV2), crates/precompiles/src/validator_config_v2/mod.rs (get_active_validators, get_next_network_identity_rotation_epoch), crates/consensus/src/dkg/manager/actor/mod.rs (handle_subscribe_dkg_ceremony, maybe_conclude_ceremony_for_epoch, conclude_ceremony).

## 12. Validator proposal procedure

When Simplex asks the leader `ℓ` (this node) to propose in round `(E, v)` with parent `(pv, pd)`:

1. If this node already holds a verified block for round `(E, v)` (a restart after broadcasting), it MUST NOT propose. The view times out instead.
2. Obtain the parent block `P = block(pd)`. If `P.number == last(E)`, re-propose `pd` (§5.3) and stop.
3. Choose `extra_data`:
   - If `P.number + 1 == last(E)` (building the boundary block): `extra_data = encode(boundary_outcome(P))` (§11), computed only after `P` has been executed and is VALID, because §11.2 reads `P`'s post-state.
   - Otherwise: this node's own finalized `SignedDealerLog` for epoch `E` (§9.4 step 5) if it has one that is not yet in a finalized block, else empty.
4. Timestamp: `t_ms = now_ms()`. If `t_ms ≤ P.timestamp_ms`, set `t_ms = P.timestamp_ms + 1`. Then `header.timestamp = t_ms // 1000` and `header.timestamp_millis_part = t_ms % 1000`. Here `timestamp_ms = timestamp * 1000 + timestamp_millis_part`.
5. `consensus_context = {epoch: E, view: v, parent_view: pv, proposer: ℓ}` (From T4; §5.1).
6. Build the block on `P` with payload attributes `timestamp`, `timestamp_millis_part`, `extra_data`, `consensus_context`, `proposer_public_key = ℓ`, `suggested_fee_recipient = 0x00…00`, `prev_randao = 0x00…00`, `withdrawals = []` and `parent_beacon_block_root = 0x00…00`. The builder SHOULD set the beneficiary to the fee recipient that ValidatorConfigV2 records for `proposer_public_key` when that is non-zero. Before T14 the beneficiary is not otherwise validated. Execution-layer validity of these fields is in 05-block-execution.md.
7. Broadcast the block (08-p2p-and-sync.md) and return its hash as the proposal payload.

Pacing is local policy and not normative. The reference implementation targets 550 ms between header timestamps, keeps a network reservation of at least 50 ms, and holds the finished proposal until its time budget runs out.

> **Open conflict C-CONS-03**: the docs say blocks come about every 600 ms from a 500 ms builder loop, but the implementation uses an adaptive estimator targeting 550 ms with a 50 ms network budget. See [conflicts](conflicts.md#c-cons-03).

Reference implementation: crates/consensus/src/consensus/application/impl.rs (build, boundary_dkg_outcome), crates/payload/types/src/attrs.rs (TempoPayloadAttributes::new), crates/payload/builder/src/lib.rs (maybe_override_fee_recipient), crates/payload/types/src/estimator/config.rs, commonware consensus/src/marshal/standard/inline.rs (propose).

## 13. Validator verification procedure

For a proposal `(E, v, pv, pd, D)` with leader `ℓ`, a validator runs these checks in order. Each step ends in one of three ways: **continue**, **reject** (the validator answers "invalid" and will never notarize this proposal), or **abstain** (no verdict and no notarize vote; the view ends by timeout or by others' certificates). A reject or abstain from one validator does not make the block invalid for others.

| # | Check | On failure |
|---|---|---|
| 1 | Obtain block `B` with `hash(B) = D`. It MUST decode as in §5.1 (body matches header, no `block_access_list_hash`). | an undecodable block is discarded; if no block is obtained, abstain |
| 2 | `epoch_of(B.number) == E` | reject |
| 3 | If `D == pd` (re-proposal): accept iff `B.number == last(E)`, and skip steps 4–10 | reject if not at `last(E)` |
| 4 | Obtain parent `P = block(pd)` and require `B.parent_hash == hash(P) == pd` and `B.number == P.number + 1` | parent unavailable: abstain; mismatch: reject |
| 5 | From T4: `B.consensus_context` is present and equals `{E, v, pv, ℓ}` | reject |
| 6 | If `is_boundary(B.number)`: `B.extra_data` decodes as an `OnchainDkgOutcome` (§10.2) | reject |
| 7 | Else, if `B.extra_data` is not empty: if the local DKG state is not at epoch `E`, abstain. Otherwise it MUST decode and check as a `SignedDealerLog` and its dealer MUST equal `ℓ` (§10.1) | abstain / reject |
| 8 | Execute `B` on `P` with the full execution-layer rules (05-block-execution.md, including the header rules: `timestamp_ms > P.timestamp_ms`, `timestamp_millis_part < 1000`, `len(extra_data) ≤ 10240`). Missing ancestors are fetched and executed first, down to the finalized tip. | INVALID (of `B` or an ancestor): reject; no verdict reached: abstain |
| 9 | Clock gate: wait until local time `≥ B.timestamp_ms`. This never rejects; it only delays the vote. | — |
| 10 | If boundary: compute `boundary_outcome(P)` (§11) and require equality with the decoded outcome of step 6, field by field (`epoch`, `output` including summary, polynomial, dealers, players and revealed, `next_players`, `is_next_full_dkg`) | cannot compute (logs or state unavailable): abstain; differs: reject |
| 11 | Accept: the validator sends its notarize vote. | — |

There is no upper bound on how far a timestamp may be ahead of local time. A block from the future only delays the votes of validators whose clocks are behind (step 9).

After finalization (Simplex finalize votes), a validator delivers finalized blocks to its execution layer in height order and acknowledges them only once they are durably persisted (08-p2p-and-sync.md).

Reference implementation: crates/consensus/src/consensus/application/impl.rs (verify, verify_header, verify_boundary_outcome, wait_until_timestamp), commonware consensus/src/marshal/standard/{inline.rs, validation.rs}, crates/consensus/src/executor/actor.rs (module documentation), crates/evm/src/consensus/mod.rs.

## 14. Epoch transition (validator)

For a validator in epoch `E`:

1. Epoch `E`'s instance finalizes the boundary block `last(E)`, possibly as a re-proposal in a later view.
2. When the finalized `last(E)` is processed in height order, the DKG component reads `outcome(E+1)` from its `extra_data`. It sets the share to the one this node concluded for that parent, or none if its local output differs from `outcome(E+1).output` or it was not a player. It persists the new state `S(E+1)` (§9.1).
3. The validator stops epoch `E`'s instance. It SHOULD keep the verification keys of the last two epochs to accept straggler certificates for `last(E)`.
4. It starts epoch `E+1`'s instance (§5.3) with `floor = hash(last(E))`, participants `outcome(E+1).output.players`, the elector version from `header(last(E)).timestamp`, and its share if it has one. It then starts the ceremony of epoch `E+1` with `info(E+1)`.

A validator that sees votes for an epoch later than its own SHOULD fetch the finalization of its current epoch's boundary block and catch up one epoch at a time (08-p2p-and-sync.md). Simplex's per-epoch vote journal MUST be persisted, so that a validator never signs two conflicting votes in one round across restarts.

Reference implementation: crates/consensus/src/epoch/manager/actor.rs (enter, exit, handle_msg_for_unregistered_epoch), crates/consensus/src/dkg/manager/actor/mod.rs (handle_finalized_header, enter_epoch, exit_epoch).

## 15. Fork-dependent consensus behaviour

| Fork | Keyed on | Behaviour |
|---|---|---|
| T0 (mainnet genesis) | — | Everything in this chapter except the rows below: elector V0, reveal V0, no header `consensus_context`, immediate verification. |
| T2 | block timestamp (EL) | The ValidatorConfigV2 precompile appears (precompiles/validator-config-and-zones.md). The consensus layer reads next players from it once it is initialized (§11.2, C-CONS-02). |
| T4 | block timestamp | Header `consensus_context` present on every block and checked by voters (§5.1, C-CONS-01). |
| T8 | block timestamp (EL) | Block execution decodes the boundary `OnchainDkgOutcome` and writes `(outcome.epoch, outcome.output.players)` to CurrentCommittee. An undecodable boundary outcome makes the block invalid (05-block-execution.md). |
| T12 | `boundary_timestamp(E)` | Leader election `RandomVersion::V1` (§6) and DKG `Reveal::V1` (§9.2) for epoch `E` and its ceremony. |
| T14 (out of scope) | `boundary_timestamp(E)` | Deferred verification by default, and beneficiary validation. Not part of T13. |

No other fork from T0 to T13 changes consensus-layer behaviour.

## 16. Versions of the commonware documentation

The normative version is the one pinned in §2.

> **Open conflict C-CONS-04**: the consensus docs page links commonware-consensus 0.0.65, but the implementation and this chapter use commonware 2026.9.0. See [conflicts](conflicts.md#c-cons-04).

## 17. Open items

> **TODO**: The rule earlier releases used to derive `next_players` and `is_next_full_dkg` from ValidatorConfig V1, for mainnet boundaries before ValidatorConfigV2 was initialized, and the height at which mainnet switched, are not in the pinned code. They are not needed to follow or validate T13 (those outcomes are trusted through certificates) and are left unspecified.

> **TODO**: The list of mainnet network-identity rotations (epochs whose ceremony was a full DKG) is not recorded in the repository except as the latest checkpoint (epoch 2042). It can be derived by decoding every boundary block (for example with `xtask identity_transitions`). It is informative only.
