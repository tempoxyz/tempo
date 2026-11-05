# Simplex consensus (Tempo profile)

This chapter specifies the Simplex BFT protocol exactly as Tempo runs it: the data types and their byte encodings, the signing messages, how votes and certificates are verified and assembled, leader election, the per-view state machine with its timers, the certificate-fetching protocol, the interface between consensus and the application, and the block-handling wrapper ("marshal Inline") that sits between them.

The protocol follows [Simplex Consensus](https://eprint.iacr.org/2023/463) by Benjamin Y. Chan and Rafael Pass, with the deviations listed in §8.1. Only the configuration Tempo uses is specified. Other configurations of the same engine (other signature schemes, stable leaders, deferred verification, block forwarding) are out of scope.

How Tempo maps blocks onto proposals, its epochs, its DKG and its application-level validity rules are in [07-consensus.md](../07-consensus.md). Channel numbering, epoch multiplexing and the transport are in [08-p2p-and-sync.md](../08-p2p-and-sync.md) and [p2p.md](p2p.md).

## 1. Conventions

### 1.1 Notation

- Encodings use the codec of [codec.md](codec.md): `varint(x)` is unsigned LEB128 with the canonical-form rules of [codec.md §3.2](codec.md#32-decoding-and-canonical-form), `u8` is one byte, `u64be` is 8 bytes big-endian, `bytes(x)` is `varint(len(x)) ‖ x`, `‖` is concatenation. A decoder MUST reject trailing bytes when it decodes a whole message.
- `union(a, b)` and `union_unique(ns, msg)` are defined in [codec.md §7.1](codec.md#71-union) and [§7.2](codec.md#72-union_unique). Signing under a namespace is described in [cryptography.md §2](cryptography.md#2-namespaced-messages).
- BLS12-381 is used in the MinSig variant: signatures are G1 points (48-byte compressed), public keys are G2 points (96-byte compressed). Signing, verification, hash-to-curve, threshold shares, partial signatures and signature recovery are in [cryptography.md §4](cryptography.md#4-bls12-381) and [§5](cryptography.md#5-threshold-bls).
- `sha256` is SHA-256 ([FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)).
- Times are durations on the node's local monotonic clock. Timeouts never affect which blocks are valid.

### 1.2 The Tempo profile

| Item | Tempo choice | Where |
|---|---|---|
| Fault model | `n` participants, `f = (n − 1) // 3`, quorum `q = n − f` ([codec.md §8](codec.md#8-fault-model-n3f1)) | §2 |
| Signing scheme | BLS12-381 threshold VRF, MinSig, threshold `q` | §4, §5 |
| Participant identity | Ed25519 public key (32 bytes); used for transport authentication and ordering, not for signing votes | §2 |
| Base namespace | `b"TEMPO"` | §4.1 |
| Digest | 32 bytes (the Tempo block hash) | §3.2 |
| Leader election | Random elector, version V0 or V1 per epoch, one view per leader term | §6 |
| Certification | Immediate (the application verifies before the notarize vote) through the Inline wrapper | §9, §10 |
| Block forwarding | Disabled | §7 |
| Start of each epoch's instance | Genesis floor at view 0 whose digest is the hash of the epoch's preceding boundary block | §8.2 |

A **term** in this profile is always exactly one view. Every view has its own leader, every view starts a term, and a nullification of view `v` covers view `v` only.

## 2. Committee and quorum

An instance of Simplex runs for one epoch `E` with a fixed committee, the ordered set `P = (p_0, …, p_{n−1})` of Ed25519 public keys sorted ascending by their 32 bytes, without duplicates ([07-consensus.md §5.2](../07-consensus.md#52-signing-scheme-and-signing-domains)). The **index** of participant `p_i` is `i`. Indices are the signer identifiers in votes, the evaluation points of threshold shares and the output of leader election.

The committee tolerates `f = max_faults(n)` faults and a quorum is `q = quorum(n)`, both defined in [codec.md §8](codec.md#8-fault-model-n3f1) (for example `n = 4` gives `f = 1`, `q = 3`).

The committee's public polynomial MUST have `n` participants and threshold (number of coefficients) `q`. A node that holds a share `s_i` for index `i` whose public value equals the polynomial evaluated at `i` is a **signer**. Any other node (including a committee member without a valid share) is a **verifier**: it runs the protocol but casts no votes and never proposes.

A signer's local index `me` is its share's index. Simplex never uses Ed25519 signatures. A received vote is attributed to its sender by the authenticated transport, and the vote's signer index MUST equal the sender's index (§5.1).

## 3. Data types and encodings

### 3.1 Epoch, View, Round

`Epoch`, `View` and `Round` (`varint(epoch) ‖ varint(view)`), their encodings and their order are defined in [codec.md §9.1](codec.md#91-epoch-view-height-and-round). View 0 of every epoch is the genesis view: it is implicitly finalized and no vote or certificate for it exists. Voting starts at view 1.

### 3.2 Digest

```text
Digest = 32 raw bytes
```

In Tempo the digest of a proposal is the 32-byte block hash ([07-consensus.md §5.1](../07-consensus.md#51-block--proposal-mapping)).

### 3.3 Proposal

```text
Proposal = round:Round ‖ parent:View ‖ payload:Digest
```

| Field | Meaning |
|---|---|
| `round` | the round `(E, v)` the proposal is made in |
| `parent` | the view of the parent proposal (0 for the epoch's genesis) |
| `payload` | the digest of the proposed block |

The proposal does not carry the parent's digest. A receiver resolves it from its own certified state (§8.5).

### 3.4 Context

The **context** of a proposal is what the application receives when asked to build or verify it (§9). It is not sent on the Simplex channels.

```text
Context = { round: Round, leader: Ed25519PublicKey (32 bytes), parent: (View, Digest) }
encoding (when needed) = Round ‖ leader[32] ‖ View ‖ Digest
```

`leader` is the key `P[leader_index(round)]` (§6). `parent` is the parent's view and digest as resolved by the node (§8.4, §8.5).

### 3.5 Attestation and the VRF signature pair

Every vote carries one **attestation**: the signer's index and two partial signatures made with its threshold share. `Attestation` and its 96-byte signature pair are defined in [cryptography.md §6.1](cryptography.md#61-vote-signature-pair):

```text
Attestation = signer:varint(u32) ‖ vote_signature:G1[48] ‖ seed_signature:G1[48]     # cryptography.md §6.1
```

- `signer` is a `varint` that MUST fit in 32 bits ([codec.md §9.2](codec.md#92-participant-index)).
- The 96 signature bytes are read as raw bytes. Decoding a vote does not decompress the points. A point that is not a valid compressed G1 point in the prime-order subgroup makes the vote **invalid at verification** (§5.1), not undecodable ([codec.md §5.7](codec.md#57-deferred-fixed-size-fields), [cryptography.md §6.2](cryptography.md#62-certificate-signature-pair)).

### 3.6 Votes

```text
Notarize = Proposal ‖ Attestation
Nullify  = Round    ‖ Attestation
Finalize = Proposal ‖ Attestation

Vote = 0x00 ‖ Notarize
     | 0x01 ‖ Nullify
     | 0x02 ‖ Finalize
```

A tag other than `0x00`, `0x01` or `0x02` is a decode error. A `Vote` is the payload of the votes channel (channel 0) after its epoch multiplexing prefix ([p2p.md §8](p2p.md#8-epoch-multiplexer), [08-p2p-and-sync.md §3.3.1](../08-p2p-and-sync.md#331-channel-0-votes)). The epoch and view of a vote are those of its round.

### 3.7 Certificates

A certificate carries the two signatures recovered from `q` attestations, as the `VrfCertificate` of [cryptography.md §6.2](cryptography.md#62-certificate-signature-pair) (96 bytes, read raw like §3.5):

```text
Notarization  = Proposal ‖ VrfCertificate
Nullification = Round    ‖ VrfCertificate
Finalization  = Proposal ‖ VrfCertificate

Certificate = 0x00 ‖ Notarization
            | 0x01 ‖ Nullification
            | 0x02 ‖ Finalization
```

Certificates carry no signer set: a threshold signature verifies against the group public key alone. A `Certificate` is the payload of the certificates channel (channel 1) and the value of a resolver response (§8.14). A bare `Finalization` (without tag) is the form stored by marshal and served to followers ([08-p2p-and-sync.md](../08-p2p-and-sync.md)).

Sizes, with `|varint(x)|` the encoded length of `x`:

| Message | Size in bytes |
|---|---|
| `Round` | `\|varint(E)\| + \|varint(v)\|` |
| `Proposal` | `\|Round\| + \|varint(parent)\| + 32` |
| `Vote::Notarize`, `Vote::Finalize` | `1 + \|Proposal\| + \|varint(signer)\| + 96` |
| `Vote::Nullify` | `1 + \|Round\| + \|varint(signer)\| + 96` |
| `Certificate::Notarization`, `::Finalization` | `1 + \|Proposal\| + 96` |
| `Certificate::Nullification` | `1 + \|Round\| + 96` |

### 3.8 Decoding rules

A decoder of `Vote` or `Certificate` MUST:

1. read the tag byte and reject unknown tags;
2. decode every `varint` canonically, rejecting values out of range of their type (u64 for epoch and view, u32 for signer);
3. read exactly 32 bytes for a digest and exactly 96 bytes for a signature pair;
4. reject the message if any input is left over.

It MUST NOT reject a message because its G1 bytes are not valid points; such a message fails verification instead (§5). The outcome for a peer is the same: a node that receives an undecodable message, or one that fails verification, blocks the sender (§8.12).

## 4. Signing

Votes and certificates are signed with the threshold VRF scheme of [cryptography.md §6](cryptography.md#6-threshold-vrf-scheme), with base namespace `NS = b"TEMPO"`.

### 4.1 Namespaces

The four namespaces `NS_NOTARIZE`, `NS_NULLIFY`, `NS_FINALIZE` and `NS_SEED` are `ns_notarize`, `ns_nullify`, `ns_finalize` and `ns_seed` of [cryptography.md §6.3](cryptography.md#63-signing-a-subject) for `NS = b"TEMPO"`. Their bytes (informative):

| Name | Value | Bytes (hex) |
|---|---|---|
| `NS_NOTARIZE` | `b"TEMPO_NOTARIZE"` | `54454d504f5f4e4f544152495a45` |
| `NS_NULLIFY` | `b"TEMPO_NULLIFY"` | `54454d504f5f4e554c4c494659` |
| `NS_FINALIZE` | `b"TEMPO_FINALIZE"` | `54454d504f5f46494e414c495a45` |
| `NS_SEED` | `b"TEMPO_SEED"` | `54454d504f5f53454544` |

### 4.2 Subjects and signed messages

A vote or certificate is about a **subject**: `Notarize(proposal)`, `Nullify(round)` or `Finalize(proposal)`. The vote namespace, vote message and seed message of each subject are defined in [cryptography.md §6.3](cryptography.md#63-signing-a-subject), with `encode(proposal)` per §3.3 and `encode(round)` per §3.1. The seed message depends only on the round, so every vote of a round, of any kind and for any proposal, carries a partial seed signature on the same message.

### 4.3 Signing a vote

A signer produces the attestation of a vote with `sign_vote(share, subject)` ([cryptography.md §6.3](cryptography.md#63-signing-a-subject)), using its share for the epoch.

BLS signing is deterministic, so a participant always produces the same bytes for the same subject. Nodes rely on this to tell a duplicate from a conflicting vote (§8.12).

## 5. Verification and assembly

### 5.1 Votes

A vote for subject `s` is **valid** iff `verify_attestation(S_E, s, attestation)` holds ([cryptography.md §6.4](cryptography.md#64-verifying-a-vote)), where `S_E` is the epoch's sharing: the signer index is below `n`, both G1 points decode, and both partial signatures verify under the signer's partial public key.

An implementation MAY verify many votes of the same subject together with a randomized batch check, and MUST then identify the individual invalid votes (for example by bisection) so that exactly the valid ones are kept ([cryptography.md §4.6](cryptography.md#46-batch-verification)).

Before verifying, a node checks the vote against its sender (§8.12): the sender MUST be a participant and the vote's signer index MUST equal the sender's index. Votes are verified lazily: a node need not verify a vote until it holds enough votes of that kind for the subject to possibly reach `q` (§8.11).

### 5.2 Assembling a certificate

From `q` valid votes of one subject with pairwise distinct signer indices, a node assembles the certificate with `assemble` ([cryptography.md §6.6](cryptography.md#66-assembling-a-certificate)), which recovers both group signatures by Lagrange interpolation ([cryptography.md §5.7](cryptography.md#57-signature-recovery)).

The recovered signatures equal the signatures of the group secret on the two messages, whatever subset of signers is used. A certificate for a subject is therefore unique, and the seed signature of a round is the same in every certificate of that round.

### 5.3 Certificates

A certificate for subject `s` in epoch `E` is **valid** iff `verify_certificate(Y_E, s, certificate)` holds ([cryptography.md §6.5](cryptography.md#65-verifying-certificates)), where `Y_E` is the epoch's group public key (the constant term of its public polynomial, [07-consensus.md §5.2](../07-consensus.md#52-signing-scheme-and-signing-domains)). When several certificates are verified in one batch, certificates of the same round MUST carry equal seed signatures, otherwise the batch is invalid.

Certificate verification needs only `Y_E` and the namespace: no participant set, no signer indices. This is what lets followers verify finalizations with a single trusted key.

### 5.4 Seed

The **seed** of round `r` is defined in [cryptography.md §6.7](cryptography.md#67-seed): the recovered `seed_signature` of any certificate of `r`. No coalition of at most `f` participants can compute it before `f + 1` honest participants have voted in `r`, but it can become known before `r` resolves, so the seed of view `v` MUST NOT be used as randomness for anything decided in view `v` itself. Tempo uses it only to elect the leader of the next view (§6).

## 6. Leader election

Each epoch's instance uses the Random elector with a version fixed for the epoch: `V0` before T12 and `V1` from T12, selected from the timestamp of the epoch's preceding boundary block ([07-consensus.md §6](../07-consensus.md#6-leader-election)).

`modulo` is defined in [codec.md §7.3](codec.md#73-modulo).

```python
def leader_index(E: int, v: int, n: int, seed: bytes | None, version: str) -> int:
    # seed: the 48-byte compressed seed_signature of round (E, v-1), taken from the first
    # valid certificate (notarization, nullification or finalization) of view v-1 the node
    # obtained. None only when v == 1.
    assert n > 0
    if seed is None:
        assert v == 1
        return (E + v) % n                     # u64 wrapping addition; E + 1 never wraps in practice
    if version == "V0":
        return modulo(seed, n)
    return modulo(sha256(seed), n)             # V1
```

The leader of round `(E, v)` is `P[leader_index(E, v, n, seed_{v−1}, version)]`. A node sets the leader of view `v + 1` as soon as it holds any certificate of view `v` (§8.9), and never changes it afterwards. Because the seed signature of a round is unique (§5.2), every honest node elects the same leader for every view whatever certificate kind it saw.

> Informative: V0 reduces the 384-bit compressed point (whose top 3 bits are encoding flags) modulo `n`; V1 hashes it first, which removes the bias of the flag bits.

## 7. Engine configuration

Tempo configures each epoch's instance as follows. Parameters marked *local* are policy and do not affect which blocks are valid; nodes SHOULD use the defaults.

| Parameter | Value | Kind |
|---|---|---|
| `epoch` | `E` | consensus |
| `namespace` | `b"TEMPO"` | consensus |
| `floor` | genesis at view 0 with digest `hash(preceding_boundary_block(E))` | consensus |
| `elector` | Random, version per §6 | consensus |
| `term_length` | 1 (fixed by the Random elector) | consensus |
| `leader_timeout` | 1,200 ms | local |
| `certification_timeout` | 2,000 ms | local |
| `timeout_retry` | 10 s | local |
| `fetch_timeout` | 2 s | local |
| `view_retention` | 256 views | local |
| `skip` | enabled, `skip_timeout` = 11.2 s, `skip_budget` = `n` | local |
| `forward` | disabled | local |
| `track_historical_votes` | true | local |

A node MUST reject a configuration where `leader_timeout = 0`, `certification_timeout ≤ leader_timeout`, `timeout_retry = 0`, `view_retention = 0`, `fetch_timeout = 0`, or (with skip enabled) `skip_timeout ≤ certification_timeout` or `skip_timeout ≤ timeout_retry`.

## 8. Protocol

### 8.1 Overview and deviations from the paper

Per view `v`: the leader proposes by broadcasting its block and its `notarize` vote; participants verify and send `notarize`; `q` notarize votes form a **notarization**; each participant then **certifies** the notarized block (§9), enters `v + 1` and sends `finalize`; `q` finalize votes form a **finalization**. A participant that times out in `v` sends `nullify(v)`; `q` nullify votes form a **nullification**, which also moves everyone to `v + 1`.

Differences from the paper's protocol:

- Notarize and nullify are distinct messages rather than votes for a block or a dummy block.
- A proposal carries only its parent's view. Missing notarizations and nullifications are fetched on demand (§8.14), not carried in proposals.
- A notarization does not by itself move a node to the next view: the node first certifies it (§8.7).
- A leader timeout (no proposal), a certification timeout, and immediate expiry on local failures and on the leader's own `nullify` (§8.8).
- Leader skipping: a leader that has been silent for `skip_timeout` while a quorum was active is nullified at once (§8.8).
- `nullify` is rebroadcast every `timeout_retry` together with a certificate that lets peers catch up (§8.8).
- Votes are verified lazily, in batches, once they can reach a quorum (§8.11).

### 8.2 State

A node keeps, per epoch instance:

```python
current: int            # the view being driven; starts at 1
last_finalized: int     # highest finalized view; starts at 0
genesis: Digest         # floor digest (hash of the preceding boundary block)
rounds: Map[int, Round] # per-view state, created on demand
```

Per view (`Round`):

| Field | Meaning |
|---|---|
| `leader` | elected leader index, once known |
| `proposal`, `status` | the proposal of this view and its status: `None`, `Unverified`, `Verified` or `Equivocated` |
| `notarization`, `nullification`, `finalization` | certificates held for this view |
| `sent_notarize`, `sent_nullify`, `sent_finalize` | own votes already sent |
| `sent_notarization`, `sent_nullification`, `sent_finalization` | certificates already broadcast |
| `certify` | `Ready`, `Pending`, `Certified(true\|false)` or `Aborted` |
| `leader_deadline`, `certification_deadline`, `retry_deadline` | timers |
| `latched` | the first early-expiry reason recorded for the view (§8.8) |

A view `u` is **certified** when it holds a finalization, or a notarization whose local certification returned `true`. The **certified payload** of `u` is that proposal's payload. View 0 is certified with payload `genesis`.

Startup: with the genesis floor, the node sets `current = 1`, `last_finalized = 0`, elects the leader of view 1 with `seed = None` and arms the timers of view 1 (§8.3). It then replays its persisted state (§8.13).

### 8.3 Entering a view

```python
def enter_view(v):
    if v <= current:
        return
    current = v
    r = rounds[v]
    r.leader_deadline        = now + leader_timeout
    r.certification_deadline = now + certification_timeout
    notify_batcher(current, r.leader, last_finalized)      # §8.8 leader skip checks
```

A node enters `v + 1` exactly when, for view `v`, it (a) certifies a notarization successfully, (b) obtains a nullification, or (c) obtains a finalization. It may jump several views at once. Views it skips never get timers and it never votes in them. The leader of the entered view was set when the certificate of the previous view arrived (§8.9).

### 8.4 Proposing

A signer `me` proposes in view `v` (with `v ≤ current + 1`) iff `rounds[v].leader == me`, it has not sent `nullify(v)`, it holds no proposal for `v`, and it has not already asked the application to build for `v`. The parent is chosen as:

```python
def find_parent(v) -> (int, Digest) | Missing:
    # the highest certified view below v, or genesis
    u = max([w for w in rounds if w < v and certified(w)], default=0)
    payload = genesis if u == 0 else certified_payload(u)
    for w in range(u + 1, v):
        if rounds[w].nullification is None:
            return Missing(w)            # wait; the resolver fetches it (§8.14)
    return (u, payload)
```

The node then calls `propose(Context{round: (E, v), leader: P[me], parent: (u, payload)})` (§9). When the application returns digest `d`:

- if `v < current`, the result is dropped;
- if the node has sent `nullify(v)` meanwhile, the result is dropped;
- otherwise `proposal = Proposal((E, v), u, d)`, `status = Verified`, the leader timer of `v` is cleared, the block is broadcast (relay, §9), and the node sends `notarize(proposal)` (§8.6), which is the proposal message.

If the application declines (closes the request), the node latches `MissingProposal` for `v` (§8.8).

### 8.5 Receiving a proposal

The proposal of view `v` is learned only from the **leader's own `notarize` vote**, received on the votes channel from the authenticated leader (the sender check of §8.12 makes the signer index equal the leader's index). It need not be signature-verified yet. A node forwards the first such proposal of a view to its voting logic once per view, and only if the leader is not itself. A proposal may also be learned from a notarization or finalization of `v` (§8.9).

On a new proposal for `v` (with `v` in the vote admission window, §8.11):

- if `sent_nullify(v)`, ignore it;
- if no proposal is recorded, record it with `status = Unverified` and clear the leader timer;
- if the same proposal is recorded, nothing changes;
- if a different proposal is recorded from a vote, set `status = Equivocated` (the node will not notarize or finalize in `v`). Once `Equivocated`, further votes do not change the proposal.

**Ancestry check.** Before verification, a node with `leader ≠ me`, `sent_nullify(v) = false` and no verification yet requested for `v` checks the proposal `p`:

```python
def parent_payload(p) -> Digest | Invalid | Wait(view, kind):
    v, u = p.round.view, p.parent
    if u >= v:                return Invalid           # parent not before proposal
    if u < last_finalized:    return Invalid           # parent below finality
    for w in range(u + 1, v):
        if rounds[w].nullification is None:
            return Wait(w, "nullification")
    if u == 0:                return genesis
    if certified(u):          return certified_payload(u)
    return Wait(u, "notarization")
```

- `Invalid`: latch `InvalidProposal` for `v` (§8.8).
- `Wait(w, kind)`: request the certificate of view `w` from the proposal's leader through the resolver (§8.14), at most once per distinct `w` per view, and retry the check when new certificates arrive.
- A payload `pd`: call `verify(Context{round: p.round, leader: P[leader], parent: (u, pd)}, p.payload)` (§9) and record `(p, pd)` as the verification binding.

When verification returns:

- `true`: if the proposal and the parent payload are still those of the binding and `status == Unverified`, set `status = Verified` and clear the leader timer; the node then sends `notarize` (§8.6). Otherwise the result is stale and is discarded.
- `false`: unless stale, latch `InvalidProposal`.
- request closed without an answer: unless stale, latch `IgnoredProposal`.

At most one proposal request and one verification request are outstanding at a time. A request for a view below `current` is abandoned.

### 8.6 Notarize

A signer sends `notarize(p)` for view `v` iff `v ≤ current + 1`, `status(v) == Verified` (built locally, or verified by the application with an unchanged binding), `sent_notarize(v) = false` and `sent_nullify(v) = false`. It sends at most one `notarize` per view, ever. A node still sends its `notarize` after it already holds a notarization of `v`.

### 8.7 Notarization, certification and finalize

When a node holds a valid notarization `N` for view `v` and `v > last_finalized`:

1. If `N.proposal` differs from the recorded proposal of `v`, the certificate wins: the proposal is replaced, `status = Equivocated`, and the leader of `v` is blocked (§8.12). If none was recorded, `N.proposal` is recorded with `status = Unverified`.
2. The node broadcasts `N` once (§8.10).
3. If `certify(v)` is `Ready`, the node calls `certify(N.proposal.round, N.proposal.payload)` (§9). Certification runs even when the node has already left `v` or sent `nullify(v)`. It is aborted only when a finalization at view `≥ v` arrives.
4. On `true`: record `Certified(true)`, `enter_view(v + 1)`, then send `finalize(N.proposal)` iff `sent_finalize(v) = false`, `sent_nullify(v) = false`, `status(v) ≠ Equivocated`, `v > last_finalized` and `v ≤ current + 1`.
5. On `false`: record `Certified(false)` and latch `FailedCertification` for `v`; the node will not build on `v` and requests a nullification of `v` from the resolver.
6. Request closed without an answer: no state change.

Certification never runs ahead of its parent: in this profile every view starts a term, so a notarized proposal is certifiable on its own once its block is available.

The **locking rule** of this profile is therefore: a node votes `finalize(v)` only if it never sent `nullify(v)`, and it never sends `nullify(v)` after `finalize(v)` (§8.8). Together with quorum intersection this guarantees that a view cannot have both a finalization and a nullification, and that a proposal of a later view can never skip a finalized view.

### 8.8 Timeouts and nullify

For the current view `v`, the next timeout is:

```python
def next_timeout(v):
    r = rounds[v]
    if r.sent_finalize or r.finalization:     return None      # cannot happen for current
    if r.sent_nullify:
        if r.retry_deadline is None:
            r.retry_deadline = now + timeout_retry
        return (r.retry_deadline, "Retry")
    if has_skip_budget() and r.latched:       return r.latched          # (time it was latched, reason)
    if r.proposal is None and r.leader_deadline: return (r.leader_deadline, "LeaderTimeout")
    if not certified_true(v) and r.certification_deadline:
        return (r.certification_deadline, "CertificationTimeout")
    return None

def has_skip_budget():
    return (current - (last_finalized + 1)) < skip_budget          # skip_budget = n
```

`latch(v, reason)` records the first early-expiry reason for `v` (later ones are ignored, and nothing is latched once `nullify(v)` was sent). It is ignored for `v < current`. A latched reason fires immediately while the skip budget lasts. Without budget the view waits for its normal deadlines. Reasons that latch:

| Reason | Trigger |
|---|---|
| `MissingProposal` | own proposal request declined (§8.4) |
| `InvalidProposal` | ancestry check failed or verification returned `false` (§8.5) |
| `IgnoredProposal` | verification request closed without an answer (§8.5) |
| `FailedCertification` | certification returned `false` (§8.7) |
| `LeaderNullify` | a `nullify` vote for the current view received from its leader (at most once per view) |
| `Inactivity` | on entering a view led by someone else: the leader is inactive (below); ignored if the view already has an unequivocated proposal |

**Leader inactivity.** A node records, per participant, the time of the last vote or certificate received from that participant on the Simplex channels. On entering view `v` with leader `ℓ ≠ me`: let `A` be the number of participants with activity in the last `skip_timeout`, and `R = q − 1` for a signer or `q` for a verifier. If `A < R`, `ℓ` counts as active. Otherwise `ℓ` is inactive iff it has no activity in the last `skip_timeout`.

**On a timeout of the current view `v`**, the node constructs `nullify(v)` unless `sent_finalize(v)`:

- First time: set `sent_nullify(v)`, clear all three deadlines and the latch, persist (§8.13), and broadcast `nullify(v)`.
- Retry (every `timeout_retry` while still in `v`): broadcast `nullify(v)` again (the same bytes) together with the best **entry certificate** for `v`: the finalization of `v − 1` if held, else the nullification of `v − 1`, else the notarization of `v − 1`, else nothing (always nothing for `v = 1`).

After `sent_nullify(v)`, the node does not propose, verify, notarize or finalize in `v`. It still certifies notarizations of `v`.

### 8.9 Handling certificates

Certificates come from the certificates channel, from local assembly (§5.2) and from the resolver. A node accepts a certificate of view `v` only if `v` is retained (§8.11), its epoch is the instance's epoch, it is valid (§5.3) and the node does not already hold one of that kind for `v`.

| Certificate of view `v` | Effects |
|---|---|
| Notarization | set the leader of `v + 1` from its seed (if not set); record it (§8.7); add `v` to the certification candidates if `v > last_finalized` |
| Nullification | `enter_view(v + 1)`; set the leader of `v + 1` from its seed; record it. Pending certification of `v` continues |
| Finalization | if `v > last_finalized`: `last_finalized = v`, drop certification candidates `≤ v` and abort pending certifications `≤ v`; `enter_view(v + 1)`; set the leader of `v + 1`; record it, replacing a conflicting proposal as in §8.7 step 1 |

A finalization of `v` finalizes its proposal and, by the parent links that each honest node checked before voting, every ancestor. The application learns finalized blocks through the reporter (§9).

### 8.10 Certificate forwarding

A node broadcasts each certificate it holds exactly once, to all peers, on the certificates channel: when it assembles it, when it receives it from a peer, or when the resolver delivers it. This rebroadcast is what lets a node that missed votes progress. A nullify retry also carries an entry certificate (§8.8). Blocks are never forwarded proactively (`forward` disabled).

### 8.11 Vote admission, lazy verification and retention

A vote of view `u` is **admitted** iff `u ≠ 0`, `u ≥ last_finalized − view_retention` (saturating at 0) and `u ≤ current + 1`. A certificate of view `u` is admitted iff `u ≠ 0` and `u ≥ last_finalized − view_retention`, however far ahead it is. Other messages are dropped silently (not a fault).

For each admitted view above `last_finalized` and at most `current + 1`, a node buffers votes per kind and verifies them in batches:

- notarize and finalize votes are verified only once the view's proposal is known, and only votes for that proposal are kept (votes for other proposals are dropped from verification but remembered for conflict detection, §8.12);
- a batch is verified when the buffered unverified votes plus the already verified ones reach `q`; invalid signers are blocked;
- as soon as `q` votes of a kind are verified, the certificate is assembled and further votes of that kind are discarded;
- own votes are added as already verified.

A notarization or finalization received for a view makes its proposal authoritative for that view's buffers.

Views below `last_finalized − view_retention` are pruned: their state, votes and certificates are forgotten.

### 8.12 Faults and peer blocking

A node blocks a peer ([p2p.md §6.7](p2p.md#67-blocking); 4 h by default) when, on the Simplex channels of an epoch it runs:

- a message does not decode;
- a message's epoch differs from the instance's epoch;
- a certificate fails verification;
- a vote comes from a non-participant, or its signer index differs from the sender's index;
- a participant sends two `notarize` (or two `finalize`) votes in one view for different proposals (equivocation), or for the same proposal with different bytes (an invalid signature);
- a participant sends two different `nullify` votes in one view;
- a participant sends `nullify` after `finalize`, or `finalize` after `nullify`, in one view;
- a vote fails signature verification;
- a notarization or finalization names a different proposal than the one the leader sent (the leader is blocked).

The threshold scheme is not attributable: partial signatures can be forged from `q` others, so vote evidence is meaningful only locally (because the sender is authenticated), never to a third party.

### 8.13 Persistence

A signer MUST durably persist, before sending any message that depends on it:

- each own `notarize`, `nullify` and `finalize` vote;
- each certificate it records (notarization, nullification, finalization);
- each certification outcome `(round, true|false)`.

All appends of one processing step are synced together before any of that step's messages are sent. On restart the node replays the records above the floor in order, restoring the `sent_*` flags, recorded proposals (an own `notarize` restores the proposal as `Verified`), certificates and certification outcomes, and re-entering views as certificates dictate. It MUST NOT send a vote that conflicts with a replayed one. The block broadcast of a proposal (§8.4) is not gated on this sync: a leader that crashes before its `notarize` is durable may rebroadcast a different block for the same round, which cannot form a conflicting certificate because the leader never signed it. The Inline wrapper additionally refuses to propose again for a round it already built a block for (§10.1).

The persisted state of an epoch MAY be deleted once the epoch's instance is stopped. A node that lost it MUST NOT vote in that epoch again ([08-p2p-and-sync.md](../08-p2p-and-sync.md)).

### 8.14 Fetching missing certificates (resolver)

Channel 2 carries the resolver protocol of [p2p.md §9](p2p.md#9-resolver-protocol), which specifies the message format and the request engine. The Simplex instance uses the key `u64be(view)`, and a response value is an encoded `Certificate` (§3.7). This section specifies what Simplex requests, serves and accepts.

**Requests.** A node requests the certificate of view `w`:

- in the background, for every view `w` with `floor < w < highest view seen in any certificate` that has no nullification, where `floor` is the highest view the node holds a finalization of or has certified;
- for the ancestry check of a proposal (§8.5), targeted at that proposal's leader;
- after its certification of `v` returned `false`, for a nullification of `v`.

Requests stay pending until answered by a settling certificate or until `w ≤ floor`; unanswered requests are retried at another peer after `fetch_timeout`.

**Serving.** For a request of view `w` a node answers, in order of preference: its highest finalization if its view `≥ w`; a notarization of exactly `w` that it certified successfully; a nullification of `w`; otherwise its floor certificate (a finalization or certified notarization at a view `≥ w`). It never serves a notarization it has not certified, or one whose certification failed. With nothing to serve it answers with the error payload.

**Validating a response** for view `w`: if every request for `w` is already settled by local state, the response is ignored without validation and the fetch ends. Otherwise decode it as a `Certificate`; it is acceptable iff it is a nullification of exactly `w`, or a notarization or finalization of a view `≥ w`, of the instance's epoch, and valid (§5.3). An unacceptable response is *invalid* in the sense of [p2p.md §9.2](p2p.md#92-requester): the requester blocks the peer and retries. An acceptable response is processed like any certificate (§8.9). If it does not settle what was asked (a notarization was needed but a nullification came, or vice versa), it is *ambiguous*: the request is retried after `retry_timeout` without faulting the peer.

## 9. Application interface

Consensus treats blocks as opaque digests and calls the application through four operations:

| Operation | Input | Output | Semantics |
|---|---|---|---|
| `propose` | `Context` | digest, or declined | build a block on `context.parent`; returning a digest commits the proposer to verifying and certifying it |
| `verify` | `Context`, digest | `true`/`false`, or closed | `true` lets the node notarize. `false` means permanently invalid for this context. A request that cannot yet be decided stays pending (abstain) |
| `certify` | `Round`, digest | `true`/`false`, or closed | `true` lets the node finalize and enter the next view. The verdict MUST be deterministic across honest nodes |
| `broadcast` (relay) | digest, plan | — | send the block of a proposal to peers (`Propose` plan: all peers) |

Each request is single-shot for its inputs: consensus does not retry it after an answer or a close (it may re-request after a restart if the result was not persisted). Activity (notarizations, finalizations, certifications and votes) is reported to the application's reporter, which in Tempo is marshal ([08-p2p-and-sync.md](../08-p2p-and-sync.md)).

## 10. Marshal Inline wrapper

Tempo plugs its block application ([07-consensus.md §12–§13](../07-consensus.md#12-validator-proposal-procedure)) into Simplex through the **Inline** wrapper, which implements `propose`, `verify`, `certify` and `broadcast` on top of marshal, the block store and fetcher. `last(E)` is the last height of epoch `E` ([07-consensus.md §4](../07-consensus.md#4-epochs)). `h(B)` is a block's height, `parent(B)` its parent digest, `digest(B)` its hash.

### 10.1 propose(ctx)

```python
def propose(ctx):
    if marshal.has_verified_block(ctx.round):     # built one before a restart
        return DECLINE                             # never propose twice in a round
    P = marshal.block(ctx.parent.digest, fetch_round=(ctx.round.epoch, ctx.parent.view))   # waits, fetching
    if P is unavailable:  return DECLINE            # fetch abandoned
    if h(P) == last(ctx.round.epoch):              # boundary re-proposal
        stage(ctx.round, P);  return digest(P)
    B = application.build(ctx, ancestry=[P, ...])  # 07-consensus.md §12
    if B is None:         return DECLINE
    stage(ctx.round, B);  return digest(B)
```

`stage` keeps the block for the relay. On `broadcast(d, Propose{round})` the staged block is sent to all peers on the block channel and stored durably as verified for `round`.

### 10.2 verify(ctx, d)

```python
def verify(ctx, d):
    B = wait_for_block(d)                          # local delivery only (block broadcast); waits, never fetches
    if epoch_of(h(B)) != ctx.round.epoch:          return False
    if d == ctx.parent.digest:                     # re-proposal
        if h(B) != last(ctx.round.epoch):          return False
        marshal.store_verified(ctx.round, B);      return True
    marshal.store_verified(ctx.round, B)           # started now, runs concurrently; not a validity claim
    P = marshal.block(ctx.parent.digest, fetch_round=(ctx.round.epoch, ctx.parent.view))
                                                   # waits, fetching from peers; if abandoned, the
                                                   # request is closed without an answer
    if parent(B) != digest(P):                     return False
    if digest(P) != ctx.parent.digest:             return False
    if h(B) != h(P) + 1:                           return False
    return application.verify(ctx, ancestry=[B, P, ...])   # 07-consensus.md §13
```

These checks enforce, before any notarize vote: **epoch membership** (a block of round `(E, v)` has its height in epoch `E`), **parent linkage** (the block's parent is the certified parent named by the context, at height exactly one less), and the **boundary re-proposal** rule (a proposal whose payload equals its parent digest is valid iff that block is `last(E)`; it is not verified again). Since the leader always re-proposes when its parent is `last(E)` (§10.1), no block above `last(E)` is ever proposed in epoch `E`, and the boundary block can be finalized in a later view than the one it was first proposed in.

### 10.3 certify(round, d)

Verification is complete before the notarize vote, so certification only ensures the block is durably stored:

```python
def certify(round, d):
    if a verify/propose of (round, d) is in progress or done:
        wait until its block is durably stored; return True
        # a re-proposal that verify rejected falls through to the next branch
    B = marshal.block(d, fetch_round=round)        # fetch from peers if not held
    marshal.store_certified(round, B)
    return True
```

`certify` never returns `false`. A node that never received the block (a leader may send it to only some honest nodes) fetches it here, so certification and the finalize vote cannot get stuck.

## 11. Test vectors

Generated with an independent program against commonware 2026.9.0. The committee is a 4-member test fixture (`n = 4`, `q = 3`) with namespace `b"TEMPO"`; the group public key is

```text
Y = 98c6e82fdf8990fa8b78df3788c45d4a36d83dd6c4e619b7b746abe12891427dd93ccd2d00596b8a87a5b084578fd2cf0a1f3a02672f4b370b2601e6425f873eafeb10a62adaa093b503a8630b89994c5f1401e62001896d2bd4f858be2cb941
```

Round `(E = 3, v = 300)`, proposal with `parent = 299` and `payload = 0xab × 32`:

| Item | Hex |
|---|---|
| `encode(Round)` | `03ac02` |
| `encode(Proposal)` | `03ac02ab02` ‖ `ab` × 32 |
| `union_unique(NS_NOTARIZE, encode(Proposal))` | `0e54454d504f5f4e4f544152495a45` ‖ `03ac02ab02` ‖ `ab` × 32 |
| `union_unique(NS_NULLIFY, encode(Round))` | `0d54454d504f5f4e554c4c49465903ac02` |
| `union_unique(NS_SEED, encode(Round))` | `0a54454d504f5f5345454403ac02` |

`Vote::Notarize` from signer 0:

```text
00 03ac02ab02 abababababababababababababababababababababababababababababababab 00
8957296a0f2580e8e0d8023d55801fb7dd6957b54325ded592d04f13f57511992ec4d4781d3fa00bbb8713c9b2b89095
b3ce77b7d44b7c09429432e573e4db5517973d83be743ae5740129775116a115e578650ba16ecf0469be3e9b11ebd952
```

`Vote::Nullify` from signer 1:

```text
01 03ac02 01
800c29921e077e4ba5fe821028e5f332846a87ce587d1d688125f7a78b2a13b1173808e2fb79391f152a6a813ae03eba
b9a9706d1de1da283c5ff061b6425e406eed2b55988d34cc441fa804a2048bb5e33b0edb6068d83fd65e6e7fa603bb0d
```

`Certificate::Notarization` assembled from signers `{0, 1, 2}` (the same bytes result from `{1, 2, 3}`), valid under `Y`:

```text
00 03ac02ab02 abababababababababababababababababababababababababababababababab
a808794eb9936c5a0c0a3c047e3a99a1ffacf6d1da4d2bb3ada9704d7b83f6ff350ca4626e32a9b9e3c208043e5c17cd
81dccd1aea60b92bfc4c7e37c11d05003a7d17d7b1008cfbd739ced5d3228cc342742c1102c011b3fbecb4815a5f0403
```

Leader of round `(3, 301)` from that certificate's seed signature (`81dccd1a…5f0403`):

| n | V0 | V1 |
|---|---|---|
| 4 | 3 | 2 |
| 7 | 6 | 1 |

Leader of round `(3, 1)` with `n = 4`: `(3 + 1) % 4 = 0`.

