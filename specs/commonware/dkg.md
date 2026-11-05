# Feldman–Desmedt DKG and resharing

This chapter specifies the distributed key generation (DKG) and resharing protocol that Tempo validators run once per epoch to produce the threshold BLS12-381 key behind consensus certificates. It defines the round information, every message and its byte encoding, the transcripts that acknowledgements and dealer logs sign, how players check dealings, how dealers build their logs, and the deterministic algorithm that turns a set of dealer logs into a public output and each player's new share.

It covers only what Tempo uses: the MinSig variant (public keys and commitments in G2), Ed25519 participant identities, the `NonZeroCounter` evaluation-point mode, the `N3f1` fault model, and transcript version V0. When to send each message, which logs a ceremony uses, and how outputs reach the chain are in [07-consensus.md §9–§11](../07-consensus.md#9-distributed-key-generation).

The construction combines the Joint-Feldman DKG of Gennaro, Jarecki, Krawczyk and Rabin ("Secure Distributed Key Generation for Discrete-Log Based Cryptosystems", [EUROCRYPT 1999](https://link.springer.com/chapter/10.1007/3-540-48910-X_21)) with Desmedt and Jajodia's redistribution of secret shares ("Redistributing Secret Shares to New Access Structures and Its Applications", George Mason University technical report, 1997). Shares travel privately between dealer and player over the authenticated, encrypted validator network ([p2p.md](p2p.md)). Nothing secret is published except the shares a dealer reveals because a player did not acknowledge them.

## 1. Notation and dependencies

- Encodings use the codec of [codec.md](codec.md): `varint` is unsigned LEB128, `u32`/`u64` are fixed-width **big-endian**, `bool` is one byte `0x00`/`0x01`, `Option<T>` is `bool ‖ T?`, `Vec<T>` is `varint(len) ‖ items`, `Set<T>` is a `Vec<T>` whose items are strictly increasing, and `Map<K,V>` is `Set<K> ‖ Vec<V>` with exactly as many values as keys (value `i` belongs to key `i`).
- `PublicKey` is a 32-byte Ed25519 public key ([cryptography.md §3.1](cryptography.md#31-ed25519-encodings), decoded as in [§3.2](cryptography.md#32-public-key-decoding)), ordered by its 32 bytes. `Signature` is a 64-byte Ed25519 signature. Verification follows ZIP-215 ([cryptography.md §3.4](cryptography.md#34-ed25519-verification)).
- `Scalar` is an element of the BLS12-381 scalar field `F_r`, encoded as 32 bytes big-endian and rejected when `≥ r` ([cryptography.md §4.2](cryptography.md#42-scalar-encoding)). `G2` is a 96-byte compressed G2 point. Decoding rejects bad encodings, points off the curve, points outside the subgroup, and the identity ([cryptography.md §4.3](cryptography.md#43-point-encoding-and-decoding)). `g` is the G2 generator.
- `Poly<G2>` is a polynomial with G2 coefficients `C_0 … C_d`, encoded as `varint(d+1) ‖ C_0 ‖ … ‖ C_d` ([cryptography.md §5.4](cryptography.md#54-public-polynomial-and-sharing-encoding)). Evaluating it at a scalar `x` gives `C(x) = Σ_k x^k · C_k`. It is a **commitment** to a scalar polynomial `a(X)` when `C_k = a_k · g`. Because decoding rejects the identity, every decoded `Poly<G2>` has exact degree `len − 1`.
- `Transcript` and `Summary` (a 32-byte BLAKE3 output) are defined in [cryptography.md §7](cryptography.md#7-transcript). §3.3 and §4 expand the exact byte sequences the DKG feeds into them.
- Participant sets are ordered sets of `PublicKey`. The **index** of a key in a set is its zero-based position. Its **evaluation point** is `x = index + 1` (the `NonZeroCounter` mode, [cryptography.md §5.3](cryptography.md#53-evaluation-points-mode)), so no participant is evaluated at 0, where the secret sits.

## 2. Fault model and derived parameters

The fault model is `N3f1` ([codec.md §8](codec.md#8-fault-model-n3f1)). In this chapter `f(n)` is `max_faults(n)` and `q(n)` is `quorum(n)` of that section, for a set of `n ≥ 1` participants.

For a round with dealers `D`, players `P` and optional previous output `prev` (§3), with `|X|` the size of a set:

| Quantity | Definition | Meaning |
|---|---|---|
| `degree` | `q(\|P\|) − 1` | Degree of every dealer polynomial and of the output polynomial |
| `required` | `max(q(\|D\|), q(\|prev.players\|))`, or `q(\|D\|)` without `prev` | Number of dealer logs the output is built from |
| `max_reveals` | `f(\|P\|)` | Most reveals a usable dealer log may contain |
| `reveal_threshold` (Reveal V0) | `f(\|P\|) + 1` | Reveals of one player needed to list it as revealed |
| `reveal_threshold` (Reveal V1) | `required − f(\|prev.players\|)` with `prev`, else `required − f(\|D\|)` | Same, counted against the contributing set |

In Tempo the dealers of a resharing round are exactly `prev.players` ([07-consensus.md §9.1](../07-consensus.md#91-roles)), so `required = q(|D|)` and, under Reveal V1, `reveal_threshold = q(|D|) − f(|D|)`.

## 3. Round information

### 3.1 Fields

Every operation of a round is bound to its **round information** `Info`:

| Field | Type | Tempo value |
|---|---|---|
| `namespace` | bytes | `b"TEMPO"` |
| `round` | `u64` | the epoch `E` in which the ceremony runs |
| `previous` | `Option<Output>` (§11) | `None` for a full DKG, else the output that opened epoch `E` |
| `mode` | `Mode` | `NonZeroCounter` (value 0) |
| `reveal` | `Reveal` | `V0` (value 0) before T12, `V1` (value 1) from T12 |
| `dealers` | `Set<PublicKey>` | epoch `E`'s committee |
| `players` | `Set<PublicKey>` | the next players chosen at the previous boundary |

The exact Tempo mapping, including the fork predicate that selects `reveal`, is in [07-consensus.md §9.2](../07-consensus.md#92-round-information). A round with `previous = None` is a **fresh DKG**: dealers deal new random secrets and the group key changes. A round with `previous` set is a **resharing**: each dealer deals its existing share and the group key stays the same.

### 3.2 Validity

Round information is valid iff all of the following hold. Tempo treats an invalid `Info` as a fatal inconsistency, since every input comes from finalized chain data.

1. `1 ≤ |dealers| < 2^32 − 1` and `1 ≤ |players| < 2^32 − 1`.
2. If `previous` is set:
   1. `previous.public.total == |previous.players|`;
   2. `previous.public.required() == q(|previous.players|)`, where `required()` is the number of coefficients of the public polynomial up to and including the last non-identity one (its exact degree plus one);
   3. every dealer is in `previous.players`;
   4. `|dealers| ≥ q(|previous.players|)`.

### 3.3 Round summary

The round summary `S_round` is a transcript (version V0) of the round information:

```text
T = Transcript.new(b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG")
T.commit(namespace)
T.commit(u64_be(round))                       # 8 bytes, big-endian
T.commit(encode(Option<Output> previous))     # 0x00, or 0x01 ‖ Output (§11)
T.commit(encode(Set dealers))
T.commit(encode(Set players))
if modes_packet(mode, reveal) is not None:
    T.commit(modes_packet(mode, reveal))
S_round = T.summarize()
```

`modes_packet(mode, reveal)` is `encode_modes([mode, reveal])`, the mode-list encoding of capacity 2 defined in [codec.md §7.4](codec.md#74-modes). If both values are zero there is no packet. For Tempo:

| `mode`, `reveal` | Packet |
|---|---|
| `NonZeroCounter` (0), `V0` (0) | none (nothing is committed) |
| `NonZeroCounter` (0), `V1` (1) | `0x80 0x01` |

`S_round` is copied into the round's output (§11) as `summary`. Rounds that differ in any field, including the reveal version, have different summaries, so their acknowledgements and logs never verify across rounds.

**Byte-level expansion (informative).** With version V0, `commit(x)` feeds `x ‖ varint(len(x))` to the hasher ([cryptography.md §7](cryptography.md#7-transcript)). `S_round` is therefore the 32-byte unkeyed BLAKE3 hash of:

```text
0x00                                                   # start tag "new"
‖ b"_COMMONWARE_CRYPTOGRAPHY_BLS12381_DKG" ‖ 0x25        # 37 bytes
‖ namespace ‖ varint(len(namespace))                   # b"TEMPO" ‖ 0x05
‖ u64_be(round) ‖ 0x08
‖ enc(previous) ‖ varint(len(enc(previous)))
‖ enc(dealers) ‖ varint(len(enc(dealers)))
‖ enc(players) ‖ varint(len(enc(players)))
[‖ 0x80 0x01 ‖ 0x02]                                   # Reveal V1 only
```

## 4. Transcripts and signatures

Every DKG signature is an Ed25519 signature over a transcript summary with an **empty namespace**. The signed message is `union_unique(b"", S) = 0x00 ‖ S` (33 bytes), where `S` is the 32-byte summary ([cryptography.md §3.5](cryptography.md#35-namespaced-ed25519-signatures)). Domain separation comes from the transcript.

```text
round_transcript = Transcript.resume(S_round)

ack_summary(dealer, pub_msg) =
    round_transcript.fork(b"ack")
        .commit(encode(dealer))          # 32 bytes
        .commit(encode(pub_msg))         # DealerPubMsg, §5.1
        .summarize()

log_summary(log) =
    round_transcript.fork(b"log")
        .commit(encode(log))             # DealerLog, §8.1
        .summarize()
```

Expanded (V0): `resume(S)` starts a BLAKE3 hasher keyed with `S` and feeds it the start tag `0x01`. `fork(label)` takes the summary `S'` of the transcript so far, starts a hasher keyed with `S'`, feeds start tag `0x02`, and commits `label`. So:

```text
K1          = BLAKE3_keyed(key = S_round, 0x01)      # summary of round_transcript
ack_summary = BLAKE3_keyed(key = K1, 0x02 ‖ b"ack" ‖ 0x03 ‖ dealer ‖ 0x20 ‖ pub ‖ varint(len(pub)))
log_summary = BLAKE3_keyed(key = K1, 0x02 ‖ b"log" ‖ 0x03 ‖ log ‖ varint(len(log)))
```

| Signature | Signer | Signed message |
|---|---|---|
| `PlayerAck.sig` | the player | `0x00 ‖ ack_summary(dealer, pub_msg)` |
| `SignedDealerLog.sig` | the dealer | `0x00 ‖ log_summary(log)` |

## 5. Messages

### 5.1 `DealerPubMsg`

The dealer's public commitment, identical for every player.

| Field | Encoding |
|---|---|
| `commitment` | `Poly<G2>`: `varint(k) ‖ k × G2[96]` |

Decoding takes a bound `max = |players|` and MUST reject `k = 0`, `k > max`, and any coefficient that does not decode as a non-identity G2 point.

### 5.2 `DealerPrivMsg`

The private share one dealer sends one player.

| Field | Encoding |
|---|---|
| `share` | `Scalar[32]`, big-endian |

Decoding MUST reject a value `≥ r` and MUST reject zero.

### 5.3 `PlayerAck`

| Field | Encoding |
|---|---|
| `sig` | `Signature[64]` over `0x00 ‖ ack_summary(dealer, pub_msg)` (§4) |

The 64 bytes are read raw. Verification, not decoding, decides whether they form a valid signature.

### 5.4 Tempo DKG channel envelope

On the DKG channel ([08-p2p-and-sync.md](../08-p2p-and-sync.md)) a message is:

| Tag | Payload | Direction |
|---|---|---|
| `0x00` | `DealerPubMsg ‖ DealerPrivMsg` | dealer → one player |
| `0x01` | `PlayerAck` | player → the dealer it acknowledges |

`DealerPubMsg` is decoded with `max = |players|` of the receiver's current round. The whole payload MUST be consumed exactly. Any other tag is invalid. The sender's identity is the authenticated peer key of the connection. The messages carry no sender field and no signature of their own.

## 6. Dealer

A dealer is a member of `dealers` that runs this section's procedures. In a resharing round, a dealer that has no share from the previous round does not deal.

### 6.1 Starting a dealing

```python
def dealer_start(info, me, share):
    require(me.public in info.dealers)
    if info.previous is None:
        a0 = random_scalar()                    # fresh DKG
    else:
        require(share is not None)              # resharing: deal our existing share
        a0 = share.private
    a = [a0] + [random_scalar() for _ in range(degree)]     # degree = q(|players|) - 1
    pub_msg = DealerPubMsg(commitment=[a_k * g for a_k in a])
    priv = {p: DealerPrivMsg(share=eval_poly(a, x(p))) for p in info.players}   # x(p) = index(p in players) + 1
    results = {p: Reveal(priv[p]) for p in info.players}     # every player starts as "reveal"
    return pub_msg, priv, results
```

`random_scalar()` MUST be uniform over `F_r` and come from a cryptographically secure source. A dealer MUST NOT send two different dealings in one round. It MUST therefore persist its polynomial, or derive it deterministically from persisted secret randomness, so that a restart reproduces the same `pub_msg` and private messages.

> Informative: Tempo derives the dealer's randomness as `Transcript.resume(seed).noise(b"dealer-rng")`, from a 32-byte secret seed generated at random when the epoch's DKG state is created and persisted with it. The derivation is local and does not affect interoperability.

The dealer sends `0x00 ‖ pub_msg ‖ priv[p]` to every player `p` it has no ack from (§5.4). A dealer that is also a player hands its own dealing to its own player procedure locally.

### 6.2 Receiving acknowledgements

```python
def dealer_receive_ack(player, ack):
    if player not in results:                     # not a player of this round
        return Error.UnexpectedPlayer
    if not ed25519_verify(player, 0x00 ‖ ack_summary(me.public, pub_msg), ack.sig):
        return Error.InvalidAck                   # not attributed to the player
    results[player] = Ack(ack)
```

An invalid ack does not prove that the player misbehaved: a dealer that equivocated can receive an honest ack for a different `pub_msg`. Tempo accepts at most the first ack each player sends, valid or not, persists every accepted ack before using it, and ignores acks once the dealer has finalized ([07-consensus.md §9.4](../07-consensus.md#94-timing-validator-behaviour)).

### 6.3 Finalizing the dealer log

```python
def dealer_finalize():
    reveals = count(r for r in results.values() if r is Reveal)
    if reveals > max_reveals:                     # f(|players|)
        log = DealerLog(pub_msg, DealerResult.TooManyReveals)
    else:
        log = DealerLog(pub_msg, DealerResult.Ok(results))   # one entry per player, in players order
    sig = ed25519_sign(me, 0x00 ‖ log_summary(log))
    return SignedDealerLog(dealer=me.public, log=log, sig=sig)
```

A `TooManyReveals` log publishes no shares and cannot contribute to the output (§8.3). It lets a dealer that heard from too few players finish without leaking more than `f` shares.

## 7. Player

A player is a member of `players`. It keeps `view: Map[dealer → (DealerPubMsg, DealerPrivMsg)]` for the round.

### 7.1 Verifying a dealing

```python
def check_pub_msg(info, dealer, pub_msg):
    C = pub_msg.commitment
    if len(C) - 1 != degree:                      # exact degree: decoded coefficients are never the identity
        return Error.InvalidCommitmentDegree
    if info.previous is not None:
        j = index(dealer in info.previous.players)
        if C[0] != partial_public(info.previous.public, j):   # Σ_k x_j^k · P_k with x_j = j + 1
            return Error.MismatchedReshareCommitment
    return OK

def player_receive_dealing(info, me, dealer, pub_msg, priv_msg):
    if dealer in view:
        return None                               # duplicate: no new ack (Tempo resends the first ack)
    if dealer not in info.dealers:
        return Error.UnexpectedDealer
    check_pub_msg(info, dealer, pub_msg)?         # propagate the error
    x = index(me.public in info.players) + 1
    if eval_commitment(pub_msg.commitment, x) != priv_msg.share * g:
        return Error.InvalidDealerShare
    sig = ed25519_sign(me, 0x00 ‖ ack_summary(dealer, pub_msg))
    view[dealer] = (pub_msg, priv_msg)
    return PlayerAck(sig)
```

`partial_public(sharing, j)` is defined in [cryptography.md §5.5](cryptography.md#55-partial-public-keys). In a resharing round the check `C[0] == partial_public(prev, j)` binds the dealer to deal exactly the share it held, which keeps the group key unchanged.

### 7.2 When to acknowledge

A player acknowledges a dealer iff `player_receive_dealing` returns an ack. It sends `0x01 ‖ ack` back to the dealer over the authenticated channel.

- A player MUST persist `(dealer, pub_msg, priv_msg)` before it releases the ack. A published ack without the matching private share leaves the player unable to derive its share (§12).
- A player MUST NOT acknowledge two different dealings from the same dealer in one round. For a repeated copy, Tempo returns the ack it already produced.
- An invalid dealing gets no ack. The dealer then reveals that player's share in its log, and every observer checks the reveal against the commitment. Tempo blocks the peer that sent the invalid dealing.

There is no complaint message. A player that gets no valid dealing from a dealer does not ack, and the reveal mechanism makes the withholding visible.

### 7.3 Restart

After a restart a player rebuilds `view` by running `player_receive_dealing` on every persisted dealing, in any order. A persisted dealing that now fails the checks indicates corrupted storage. If a log the player can verify holds this player's valid ack for a dealer missing from `view`, the player's state is corrupt and it cannot derive a share for this round. It SHOULD then finish the round as an observer.


## 8. Dealer logs

### 8.1 `DealerLog` encoding

```text
DealerLog    = DealerPubMsg ‖ DealerResult
DealerResult = 0x00 ‖ Map<PublicKey, AckOrReveal>        # Ok
             | 0x01                                      # TooManyReveals (no payload)
AckOrReveal  = 0x00 ‖ PlayerAck                          # Ack:    1 + 64 bytes
             | 0x01 ‖ DealerPrivMsg                      # Reveal: 1 + 32 bytes
```

The `Ok` map is encoded as `varint(m) ‖ key_1 ‖ … ‖ key_m ‖ varint(m) ‖ value_1 ‖ … ‖ value_m`.

A decoder given the bound `max = |players|` MUST reject a log when any of these holds:

- the `DealerPubMsg` is invalid under §5.1 with this `max`;
- the `DealerResult` tag is neither `0x00` nor `0x01`;
- `m > max` (the decoder accepts `m = 0`);
- the map keys are not strictly increasing, or one is not a valid Ed25519 public key;
- the second length prefix differs from `m`;
- an `AckOrReveal` tag is neither `0x00` nor `0x01`;
- a revealed scalar is `≥ r` or zero.

The decoder does **not** check that the map's keys equal the round's players. Validation does (§8.3).

### 8.2 `SignedDealerLog`

| Field | Encoding |
|---|---|
| `dealer` | `PublicKey[32]` |
| `log` | `DealerLog` (§8.1), decoded with `max = \|players\|` |
| `sig` | `Signature[64]` |

```python
def check(signed, info):
    if not ed25519_verify(signed.dealer, 0x00 ‖ log_summary(signed.log), signed.sig):
        return None
    return (signed.dealer, signed.log)
```

`log_summary` commits to `encode(log)`. The encoding is canonical, so this equals the log's bytes as received. `check` authenticates the log and binds it to the round. It does not check that `dealer` is one of the round's dealers or that the log's contents are valid (§8.3).

How Tempo carries a `SignedDealerLog` in a block header, and which logs a ceremony collects, is in [07-consensus.md §10.1](../07-consensus.md#101-signeddealerlog-in-regular-blocks) and [§11.1](../07-consensus.md#111-ceremony-output).

### 8.3 Validating a log against the round

Each authenticated `(dealer, log)` pair is **usable**, **unavailable** or **faulty**. Only usable logs contribute to the output. The classification is deterministic, so every node classifies a log the same way.

```python
def classify(info, dealer, log):
    if dealer not in info.dealers:
        return UNAVAILABLE                        # unexpected dealer: never usable
    if check_pub_msg(info, dealer, log.pub_msg) is not OK:          # §7.1
        return FAULTY
    if log.results is TooManyReveals:
        return UNAVAILABLE
    if log.results.keys() != info.players:        # same keys, hence same order
        return FAULTY
    reveals = 0
    for p, r in log.results:
        if r is Ack:
            if not ed25519_verify(p, 0x00 ‖ ack_summary(dealer, log.pub_msg), r.sig):
                return FAULTY
        else:  # Reveal
            reveals += 1
            if reveals > max_reveals:             # f(|players|)
                return FAULTY
            x = index(p in info.players) + 1
            if eval_commitment(log.pub_msg.commitment, x) != r.share * g:
                return FAULTY
    return USABLE
```

An implementation MAY verify the acks of one log as an Ed25519 batch ([cryptography.md §3.6](cryptography.md#36-ed25519-batch-verification)). An empty batch is invalid under that section, but the batch is never empty here: a log reaching the batch check has at most `f(|players|)` reveals, so it has at least `|players| − f(|players|) ≥ 1` acks. It MAY verify the log's reveals together as one randomized linear combination: with fresh random scalars `ρ_1 = 1, ρ_2, …`, check `Σ ρ_i · C(x_i) == (Σ ρ_i · s_i) · g`. Either shortcut MUST accept exactly the logs that the individual checks accept, except with negligible probability.

Unavailable and faulty differ only for diagnostics: a faulty log proves the dealer misbehaved, an unavailable one does not. Neither kind is used.

## 9. Log collection and selection

A round's **log collection** maps each dealer key to at most one authenticated `DealerLog`. Recording a second log for a key replaces the first. [07-consensus.md §11.1](../07-consensus.md#111-ceremony-output) fixes which log Tempo records per dealer (the oldest on the boundary block's ancestry), so every node starts from the same collection.

Selection is deterministic:

```python
def select(info, logs):
    usable = [(d, l) for (d, l) in sorted(logs.items(), key=dealer_bytes)   # ascending dealer key
              if classify(info, d, l) == USABLE]
    if len(usable) < required:
        return Failure.InsufficientLogs
    return usable[:required]                      # the first required usable logs
```

The selected set always has exactly `required` dealers, even when more usable logs exist. An implementation MAY stop classifying once it has found `required` usable logs in key order, since later logs cannot change the selection.

## 10. Computing the output

`observe(info, logs)` returns a failure or an `Output`. Any node can run it, including one that is neither dealer nor player.

```python
def observe(info, logs):
    selected = select(info, logs)?                # §9; a Failure propagates
    return reckon(info, selected).output

def reckon(info, selected):
    # 1. Revealed players
    counts = {}
    for (d, log) in selected:
        for p, r in log.results:
            if r is Reveal:
                counts[p] = counts.get(p, 0) + 1
    revealed = Set(p for p, c in counts.items() if c >= reveal_threshold)    # §2

    # 2. Public polynomial
    if info.previous is None:                     # fresh DKG
        public = Σ_{(d, log) in selected} log.pub_msg.commitment            # coefficient-wise sum
        weights = None
    else:                                         # resharing
        X = {d: index(d in info.previous.players) + 1 for (d, _) in selected}
        weights = {d: Π_{e ≠ d} X[e] / (X[e] - X[d]) for d in X}            # Lagrange weights at 0, in F_r
        public = Σ_d weights[d] · selected[d].pub_msg.commitment            # coefficient-wise
        assert public[0] == info.previous.public.constant                  # guaranteed by §7.1

    output = Output(
        summary  = S_round,                                                 # §3.3
        public   = Sharing(mode=info.mode, total=|info.players|, poly=public),
        dealers  = Set(d for (d, _) in selected),
        players  = info.players,
        revealed = revealed,
    )
    return output, weights
```

Every selected commitment has `degree + 1 = q(|players|)` coefficients, so `public` has the same length. Its constant term is the group public key. In a fresh DKG it is the sum of the selected dealers' secrets times `g`. In a resharing it equals the previous group key. The new sharing's threshold is `q(|players|)`.

`revealed` lists the players whose shares may be reconstructible from published reveals. It changes no share and does not affect the output's validity. Tempo records it on chain as part of the output.

If `observe` fails, the round has no output. Tempo then carries the previous output and shares forward unchanged ([07-consensus.md §11.1](../07-consensus.md#111-ceremony-output)).

## 11. `Output` and `Sharing` encodings

### 11.1 `Output`

| Field | Encoding | Decode bound (Tempo) |
|---|---|---|
| `summary` | `Summary[32]` | — |
| `public` | `Sharing` (§11.2) | `max_participants = 65535`, mode version 0 |
| `dealers` | `Set<PublicKey>` | `1 ≤ len ≤ 65535` |
| `players` | `Set<PublicKey>` | `1 ≤ len ≤ 65535` |
| `revealed` | `Set<PublicKey>` | `0 ≤ len ≤ 65535` |

Two outputs are equal iff every field is equal. Polynomials compare coefficient by coefficient, with missing high coefficients treated as the identity.

### 11.2 `Sharing`

`Sharing` (`mode:u8 ‖ total:u32_be ‖ Poly<G2>`), its decoder and its partial public keys are defined in [cryptography.md §5.4](cryptography.md#54-public-polynomial-and-sharing-encoding) and [§5.5](cryptography.md#55-partial-public-keys). Outputs decode it with `max_participants = 65535` and mode version 0.

The decoder does not check that `total == |players|` or that the polynomial has `q(total)` coefficients. A node MUST NOT reject a decoded output for these reasons. Every output §10 produces satisfies them, and §3.2 checks them when an output is used as `previous`.

The `OnchainDkgOutcome` that embeds an `Output` in boundary headers is in [07-consensus.md §10.2](../07-consensus.md#102-onchaindkgoutcome-in-boundary-blocks).

## 12. Player share derivation

A player derives its new share from the same selected logs:

```python
def player_finalize(info, me, view, logs):
    selected = select(info, logs)?                # Failure: the round failed for everyone
    s = {}
    for (d, log) in selected:
        own = view.get(d)
        if own is not None and own.pub_msg == log.pub_msg:
            s[d] = own.priv_msg.share             # our persisted dealing
        elif log.results[me.public] is Reveal:
            s[d] = log.results[me.public].share   # validated reveal (§8.3)
        elif own is not None:
            return LocalError.InvalidPersistedDealing   # stored dealing does not match the log
        else:
            return LocalError.MissingPlayerDealing      # the log says we acked, but we have no dealing
    output, weights = reckon(info, selected)      # §10
    if weights is None:
        private = Σ_d s[d]                        # fresh DKG
    else:
        private = Σ_d weights[d] · s[d]           # resharing, same weights as §10
    return output, Share(index=index(me.public in info.players), private=private)
```

All arithmetic is in `F_r`. The share's evaluation point is `index + 1`, and `private · g == partial_public(output.public, index)`.

- A `Failure` here happens exactly when `observe` fails: the round has no output.
- A `LocalError` means only this player's state is unusable, and `observe` still succeeds with the same output. Tempo then continues as an observer and has no share in the next epoch.

`Share` is a local value. Its encoding, used only in local storage and configuration, is `varint(index) ‖ Scalar[32]` with a non-zero scalar ([cryptography.md §5.2](cryptography.md#52-share-encoding)).

## 13. Size of a signed dealer log

With `n = |players|`, `q = q(n)`, and `k` reveals among the `n` results (`k ≤ f(n)`):

```text
|SignedDealerLog| = 32                                     # dealer
                  + len(varint(q)) + 96·q                  # DealerPubMsg
                  + 1                                      # DealerResult tag
                  + len(varint(n)) + 32·n                  # keys
                  + len(varint(n)) + 65·(n − k) + 33·k     # values
                  + 64                                     # signature
```

For `n = 4` with no reveals this is `32 + 289 + 1 + 129 + 261 + 64 = 776` bytes. A `TooManyReveals` log is `32 + len(varint(q)) + 96·q + 1 + 64` bytes. Tempo requires every DKG artifact in a header to fit in 10,240 bytes ([07-consensus.md §3](../07-consensus.md#3-constants)).

## 14. Security notes (informative)

- **Reveals under synchrony.** If messages arrive within a bound `t` and dealers finalize after `2t`, no honest dealer reveals an honest player's share. At most `f` selected dealers are Byzantine, so the reveals they publish cannot expose an honest player's final share.
- **Reveals under asynchrony.** A partitioned network can make honest dealers reveal up to `f` honest players' shares. Byzantine players could then hold up to `2f` shares. That weakens the threshold for consensus certificates but never lets an outsider recover the secret. The output's `revealed` set records the affected players.
- **Degree.** Each usable log carries at least `q` verified evaluations (honest acks of checked shares plus checked reveals), so each selected commitment fixes a polynomial of exact degree `degree`. The aggregate keeps that degree unless an adversary solves a discrete logarithm.
- **Bias.** Joint-Feldman lets an adversary bias a fresh group key by `O(log n)` bits. This does not affect BLS signature security.

## 15. Test vectors

These vectors were produced with the library this chapter describes. Ed25519 private keys are [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) 32-byte seeds. Dealer polynomials were sampled at random, so the vectors give the resulting messages. An implementation can check the encodings, summaries, signatures (Ed25519 signing is deterministic) and the output computation.

Keys, whose public keys sort as key2 < key1 < key4 < key3:

| Key | Seed | Public key |
|---|---|---|
| key1 | `01` × 32 | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| key2 | `02` × 32 | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| key3 | `03` × 32 | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| key4 | `04` × 32 | `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c` |

### 15.1 Vector A: fresh DKG, one dealer, one player

`namespace = b"TEMPO"`, `round = 0`, `previous = None`, `dealers = players = {key1}`, so `degree = 0` and `required = 1`.

```text
S_round (Reveal V0) = f8e18b22ec48af9711c42bbddf8c805c22d3673313aeb073593e4873f6141166
S_round (Reveal V1) = 91a809fb00d945bcd21af02f45688d6ab0ac6c2f441f717e901b18acfe5d0144
```

The rest of vector A uses Reveal V1. Each line shows one field; concatenating a block's lines gives its encoding.

```text
DealerPubMsg =
  01
  a518c1f0e33b6aca2e70eb66ca4035c6021f5c522e1b0fabef7e07233ac909212b98749bced78ec9748a52dfcf80b1fe0410388d0a8846d897f417c84c6cc52ed1eb03dbbedf5dfe5e701dfa01ba45ebc1fa43bfff12395c4da431e55793a86d
DealerPrivMsg = 546d7a80a20575df170539c2658a9b3a8a75d9cc6a2e8ee27a135ef5aae505b1
PlayerAck     = dea2fd3e258995912a6134be546227bf8bac7906143433fef1654309a6c9f2419e59bb6329f876e4c4bf27636741e5431b1865cee9945823b788ef67f2636f03

SignedDealerLog =
  8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c     # dealer = key1
  01 a518c1f0…55793a86d                                                # DealerPubMsg
  00                                                                   # DealerResult: Ok
  01 8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c  # keys
  01 00 dea2fd3e…f2636f03                                              # values: Ack(PlayerAck)
  98784623737c7faf6abd1c38559d9fc059a84294dc0592b575b24e9e53e0fbc18defc9ed279385342f4760162a8cf1d10b2c80202b7f1990f95c454412019c04   # sig

Output =
  91a809fb00d945bcd21af02f45688d6ab0ac6c2f441f717e901b18acfe5d0144     # summary = S_round (V1)
  00 00000001 01 a518c1f0…55793a86d                                    # Sharing: mode, total, poly
  01 8a88e3dd…b40f6f5c                                                 # dealers
  01 8a88e3dd…b40f6f5c                                                 # players
  00                                                                   # revealed (empty)

Share (key1) = 00 546d7a80a20575df170539c2658a9b3a8a75d9cc6a2e8ee27a135ef5aae505b1
```

With degree 0 the share is the dealer's secret, and `commitment[0] = share · g`.

### 15.2 Vector B: resharing vector A to four players

`round = 1`, `previous` = vector A's output, `dealers = {key1}`, `players = {key2, key1, key4, key3}` (sorted order), Reveal V1. So `degree = 2`, `required = 1`, `max_reveals = 1` and `reveal_threshold = 1 − f(1) = 1`. The dealer deals its vector A share. key3 does not acknowledge, so the log reveals its share.

```text
S_round = 12df552e79bc5230f87b416077da527c0324231ba053398ea99528d7720a37da

DealerPubMsg =
  03
  a518c1f0e33b6aca2e70eb66ca4035c6021f5c522e1b0fabef7e07233ac909212b98749bced78ec9748a52dfcf80b1fe0410388d0a8846d897f417c84c6cc52ed1eb03dbbedf5dfe5e701dfa01ba45ebc1fa43bfff12395c4da431e55793a86d
  b9453f42850845bf85a899886521a8601eac88e6e16d13943af610b51822f9c88fe01fbde5cc778f36229475bb777e870d9779c614843bf2fe49081a46711cf214a3ef959f01a8f329af4569e9d20e1bc3dcbff89eaaebefa0453b53639b2659b8
  0d7a6bd3c7fb2c1eb3e271fcb9eb17fa409447e3de289c4196e3f5f6d7cbf13018123b69db101b286c594db2b9761a0582389c06b4344f9d9429f52780228d10a2f0b4cd2e7e3f30807cb9377c19a3bc99acb9c7df786272afae4038e66524

ack_summary(key1, DealerPubMsg) = 49043a2a6b912031eb0d4aee3c2758017e7d3f6ae28c40ab8454e02b3e658440

DealerPrivMsg to key2 = 4c2043f398205b1c0a61d5fe05acf2de7b18316ffb7edd425ddcae89919c0b2d
DealerPrivMsg to key1 = 14c1443a5081492e2557c0cccee3eb37716c36e93d6f37385401109120897593
DealerPrivMsg to key4 = 223e22a7f4c5bd5d9b20d236cad15c4ac12f8e3b2ffdf8c35c80850b57ad44e4
DealerPrivMsg to key3 = 00a937e95b503a6238833233efd36e1316a49362d32cc5e4775b0bf93707791f

PlayerAck from key2 = 14aa450125a322a571b8b16df24081650faa7548f722f28fafd740d97db21019bcf4501ba292e2a694240df2b40936b008f7caf805cf1dd56c3e0f2ec9d5e506
PlayerAck from key1 = 5bf7c1180dc9e3b76e6976b953a2c5eb63fd9231cbe2f038dc7914263a9d25fcdfd503c954ff2b1e176b51814b107913b0d897ceb7e8d63d88732d0fe3bc3208
PlayerAck from key4 = cf976d329cc9b8d6c65950b9b1634d9f0f8bce9ca45c29d7cce83fea8b8a01f40868a677a255e22c1a000011dbf588d4657016b7db7f6e60416cb483213fff05

SignedDealerLog =
  8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c     # dealer = key1
  03 a518c1f0… b9453f42… 0d7a6bd3…                                     # DealerPubMsg
  00                                                                   # Ok
  04 8139770e…8fc9b394 8a88e3dd…b40f6f5c ca93ac17…dbdabe7c ed4928c6…ac8737d1   # keys, in players order
  04 00 14aa4501…c9d5e506 00 5bf7c118…e3bc3208 00 cf976d32…213fff05 01 00a937e9…3707791f   # Ack, Ack, Ack, Reveal
  146234150ca0c4784e19079a8b0611f7e16f63501380353258013ef4ba04b121aaa2e9c42cf47fb8fe8278094829659a5687e3ab0a07416edf096d35c9f0460a   # sig

Output =
  12df552e79bc5230f87b416077da527c0324231ba053398ea99528d7720a37da     # summary
  00 00000004 03 a518c1f0… b9453f42… 0d7a6bd3…                         # Sharing (one dealer, weight 1)
  01 8a88e3dd…b40f6f5c                                                 # dealers
  04 8139770e… 8a88e3dd… ca93ac17… ed4928c6…                           # players
  01 ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1  # revealed = {key3}

Share (key2) = 00 4c2043f398205b1c0a61d5fe05acf2de7b18316ffb7edd425ddcae89919c0b2d
Share (key1) = 01 14c1443a5081492e2557c0cccee3eb37716c36e93d6f37385401109120897593
Share (key4) = 02 223e22a7f4c5bd5d9b20d236cad15c4ac12f8e3b2ffdf8c35c80850b57ad44e4
Share (key3) = 03 00a937e95b503a6238833233efd36e1316a49362d32cc5e4775b0bf93707791f   # taken from the reveal
```

The output's constant term equals vector A's group key, as resharing requires. Each `…` abbreviates the full value given earlier in the same vector.

