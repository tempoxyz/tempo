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

These vectors were produced with the library this chapter describes. Ed25519 private keys are [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) 32-byte seeds. Dealer polynomials were sampled at random, so the vectors give the resulting messages. An implementation can check the encodings, summaries, signatures (Ed25519 signing is deterministic) and the output computation. Vectors A and B have one dealer each. Vectors C and D combine several dealers, fresh and resharing.

Keys, whose public keys sort as key5 < key2 < key1 < key4 < key3 (key5 appears only in vector D):

| Key | Seed | Public key |
|---|---|---|
| key1 | `01` × 32 | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| key2 | `02` × 32 | `8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394` |
| key3 | `03` × 32 | `ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1` |
| key4 | `04` × 32 | `ca93ac1705187071d67b83c7ff0efe8108e8ec4530575d7726879333dbdabe7c` |
| key5 | `05` × 32 | `6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1` |

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
  b9453f42850845bf85a899886521a8601eac88e6e16d13943af610b51822f9c88fe01fbde5cc778f36229475bb777e870d9779c614843bf2fe49081a46711cf214a3ef959f01a8f329af4569e9d20e1bc3dcbff89eaaebefa0453b53639b2659
  b80d7a6bd3c7fb2c1eb3e271fcb9eb17fa409447e3de289c4196e3f5f6d7cbf13018123b69db101b286c594db2b9761a0582389c06b4344f9d9429f52780228d10a2f0b4cd2e7e3f30807cb9377c19a3bc99acb9c7df786272afae4038e66524

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
  03 a518c1f0… b9453f42… b80d7a6b…                                     # DealerPubMsg
  00                                                                   # Ok
  04 8139770e…8fc9b394 8a88e3dd…b40f6f5c ca93ac17…dbdabe7c ed4928c6…ac8737d1   # keys, in players order
  04 00 14aa4501…c9d5e506 00 5bf7c118…e3bc3208 00 cf976d32…213fff05 01 00a937e9…3707791f   # Ack, Ack, Ack, Reveal
  146234150ca0c4784e19079a8b0611f7e16f63501380353258013ef4ba04b121aaa2e9c42cf47fb8fe8278094829659a5687e3ab0a07416edf096d35c9f0460a   # sig

Output =
  12df552e79bc5230f87b416077da527c0324231ba053398ea99528d7720a37da     # summary
  00 00000004 03 a518c1f0… b9453f42… b80d7a6b…                         # Sharing (one dealer, weight 1)
  01 8a88e3dd…b40f6f5c                                                 # dealers
  04 8139770e… 8a88e3dd… ca93ac17… ed4928c6…                           # players
  01 ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1  # revealed = {key3}

Share (key2) = 00 4c2043f398205b1c0a61d5fe05acf2de7b18316ffb7edd425ddcae89919c0b2d
Share (key1) = 01 14c1443a5081492e2557c0cccee3eb37716c36e93d6f37385401109120897593
Share (key4) = 02 223e22a7f4c5bd5d9b20d236cad15c4ac12f8e3b2ffdf8c35c80850b57ad44e4
Share (key3) = 03 00a937e95b503a6238833233efd36e1316a49362d32cc5e4775b0bf93707791f   # taken from the reveal
```

The output's constant term equals vector A's group key, as resharing requires. Each `…` abbreviates the full value given earlier in the same vector.

### 15.3 Vector C: fresh DKG, four dealers, one log excluded

`namespace = b"TEMPO"`, `round = 0`, `previous = None`, `dealers = players = {key2, key1, key4, key3}` (sorted order), Reveal V1. So `degree = 2`, `required = q(4) = 3`, `max_reveals = f(4) = 1` and `reveal_threshold = 3 − f(4) = 2`. Player evaluation points are key2 → 1, key1 → 2, key4 → 3, key3 → 4.

The vector exercises three paths:

- **TooManyReveals.** key2 gets acks only from key2 and key1. Two reveals exceed `max_reveals`, so its log is `TooManyReveals` and unavailable (§8.3).
- **Reveals.** key3 does not acknowledge key1 or key4. Their logs reveal key3's share, and key3 takes those two shares from the reveals (§12).
- **Revealed set.** Two selected logs reveal key3, which meets `reveal_threshold`, so `revealed = {key3}`.

The usable logs in key order are key1, key4 and key3. That is exactly `required`, so all three are selected.

Each dealer's block gives its `DealerPubMsg`, its `ack_summary` (§4), its private message to every player, and its signed log's `log_summary` and signature. The four private messages fix the dealer's degree-2 polynomial. The acks are omitted: each is the deterministic Ed25519 signature of the acknowledging player over `0x00 ‖ ack_summary`. A `TooManyReveals` log encodes as `DealerPubMsg ‖ 0x01`. An `Ok` log encodes per §8.1, with entries in players order. The signed logs are 386 bytes (key2), 744 bytes (key1 and key4, one reveal each) and 776 bytes (key3).

```text
S_round = 616b3ee69839819877dc1766879d3ec6551fc4075a02c04868958048c9a55987

# dealer key2
DealerPubMsg =
  03
  80b2a5545afafde5de487c5a5580afa792cb4d782bc3e3547b04d8acec0035a38f3e0b682a623507c3dce0f53318698003c48192069cfc36dd183f5304212bde32246c5282fc81c3e45350e86768dbc5c064063bb1e68f5ba19a6b6ab6028cd1
  91f947ddb784d8291dbed2dc1e2945e91b5a974471f24a3500cd3099973ee4d0e1e07157f28b7d28eba34752554b9ef207b1a2ce2b77dd15a6a76b67cda95750137313448844c86931f0929c73d5ff5b3ddbc3ec969654175f42971efaaa10c8
  a4c64b119ae24ad29e3e92568fa4d637e5165e6c74f6c27cd66bef1334046b8e2012b42b7159dff13b80386672a22a170c6df504c4c1cb3fc950920f38381b869ad7e7a0656966d7bff70a3f7b3a44750be5708ca38b182768592806282d3f90
ack_summary = d3001625050c60558d082467437961000d813c4f831e0f4fe3b7a84f33e5572f
DealerPrivMsg to key2 = 2756c64731deabce6d550dc24097f8570e3f291a2661a87b31b1ee624c2c7748
DealerPrivMsg to key1 = 4bd894ee8cf461aca6164ff7fc34e824bc82ac93933aa7a7021aa13202440cbd
DealerPrivMsg to key4 = 5d0859782e95b76cc93f5f9eff229e21806667e53026fb704e3ffd2dd75669e9   # not acknowledged
DealerPrivMsg to key3 = 5ae613e416c2ad0ed6d03cb749611a4d59ea5b0efd26a3d716220255cb638ecc   # not acknowledged
log_summary = e0e416b5f7cf84f654cbca3cca789fd593a6a235f8aa13780666269e70a37377
SignedDealerLog.sig = 2e78607af86879456c68c501719bb5c2e45d6f2670d6889bc9d299ca7823e83d99792685cf3857f1caf28ae592be2938e28f2feae07d4abbe143a371411b3603

# dealer key1
DealerPubMsg =
  03
  b2c90dbecbd3ee46dfc83987b753d7ee19db8e386621ccdba973dc2058f679fedcd924d963b6d1dce0392fd11159273a0d2fed832820b7d108eeacb5126ddd54e1e6f4113736f603d990f5723241bc06d76538a551b301a6c95373c7f5d524cb
  adccf782d84ebc61440bb1a6d084671c85621ceaa2ec46781dced6b67d8970849d626f7d7f1a4c9b0904ddfdb672ef0e14a7089872c52de0c9f09bf465ccf536f61fccc34e07a99c45f8574444d21e8674978610cb6fb150e432bb011fe84297
  982e05412cc352b8c48ffe0f0fb2c62a2f7b7b5cc56a9a9de3629fa335ec073aac70d790f26e865609d0947ee14e2a8e0a893ae53b64f357be95c46a64c03d6d061793f548985c3f7fe7598a03be5d293c265df1b93242531c67e62373b88058
ack_summary = 0a51212ecb17e57f488934a7535a0460bfca5f0d2a6bad8aac872695d2033b14
DealerPrivMsg to key2 = 0eb79032d0af10ab5e2b47491a1bff843b2043f4761c9dcb4942a5141f3d6ec6
DealerPrivMsg to key1 = 6cc4f03bfa852a3ab520211948c96a73c34a7ac31db5fbc3eb109dcb81763bd5
DealerPrivMsg to key4 = 6b03328e15a7f42e6c873f83444a382a8f8b784166eb73dd9ffa1e8c73c7ebc1
DealerPrivMsg to key3 = 0972572922176e868460a2870c9e68a89fe33c6f51bd061867ff2756f6327e8a   # not acknowledged
log_summary = 0d09781b57208436beb601ac00b15d143ec12225cce2620ea1a7b9b35ee01919
SignedDealerLog.sig = 1b566623422b480976a50b987764bb3284cfccc690a9e4a037ed65774a54df8cd1b4e95e0361e867aef5a0198f8b33f24175bd26b40a3a70672a59fdfa7acb04

# dealer key4
DealerPubMsg =
  03
  84f93bfac92c55f0aa8d10f55ece88e560c90d4d4056e2e7ced1634458125e9fcbf1d8dc3d2f762d8562ea1d20c597340841b771ff2f9356c1102d891bf6dfee31b303dd15839923ea02a33e086a93370bd385252ea53480a7bd629e8cacefea
  81e906e3065d1766d8cd549c4a37152cf0c6de29fbef3d1ff9c121a0f13fc3c288115434c8764248fa653a3675a5f3370517ae9caee7e849f95e884381b689eea619e2765957cc9853668cbd77c901feef400456c0135e1d76c9554eb87bfb9f
  a220ff66900192f4bf908d2fa38b1783b660eafd58f563cb1d62521a74a96a2cfb44103c2fa0ece55f5291d63a5a40bf00d15bc7ef4a2ddbb42f0d57d34cbb0b99f5ef06653026e400242036666ae2881390911eecab240999850fe3531e0cff
ack_summary = 26de2fc8722e6b51b2baa379be213138c62f0f70e73b5a6cd1da06ef5fa8ea9f
DealerPrivMsg to key2 = 0326cb5423e768b8785f1a18d6898b8f239c784d2e0a73c21aaddd653e00f1fd
DealerPrivMsg to key1 = 42fce55e994429adee5e39663d2c998a5656b1a9172e7bba353b688acec5dd9a
DealerPrivMsg to key4 = 2642c587d10c86d71ca4552dc971aaf4c513a9171f3ffe5d78cdf8d39848326e
DealerPrivMsg to key3 = 20e61322f4ddfd7c366b457784fa97d3c391029a463d57aae5658e3e9a87f07a   # not acknowledged
log_summary = 45af0ccce2a6012d749c2fd4fecacc36edbb1b23ac179f4267bbd1a11216101d
SignedDealerLog.sig = 972c3d8fd08903ac096da5e49f137ffcae495a1e13dc64d97c649bda327a6a6b48378487a35f6897ff81468eca9488041647fe6cdc1b7adfc18694a8dbd7b400

# dealer key3
DealerPubMsg =
  03
  941e5f65892b25834560917363d2ad9cd56c670b9af17a40aa5e4d5d1656d3f0fb6c5ed140c4086003ca3a82dfadcd2b11e14acdacd19615051b8d56cc97b2f2a258e6914ad2abe12a8b4b9b2c1a2302873bc522810d7e01fc109fe4dfd04cc0
  98bd629dcec2f49c0f0befd1f12a6560cf3e950273f5f2e35708cf520a8906b780a15d7a7e2cb4d48aa216ca1c7cff7312bb855b2f2859c4352142010e8eeef0e0a0fe3d6a6332af27d368a6aa9bba8c3892def4fa2156050589e8d6a977355d
  87af5605017a0a853c933a04d5374106f523605fca91c7749a29878d4a8f2f12cb4af98ebcaac2b7fd7ec9cecfc749ab135063db9b56501da4510629099d7c0f7a04c8a17d6c8e041f6450902378c7281ecf1e1512071025c7a44a5289ecbd7a
ack_summary = 5797d2096d28ea3cbb20b89c673daf33808a1929a2c638ad733dff9b754cef6d
DealerPrivMsg to key2 = 664bd59cd21f7aa8d41802adfc20193f5a35e6d53495c9048563538c3fdce692
DealerPrivMsg to key1 = 156913e4f6d90d8644a2450a2921bd9f8abe7b09cd08380de72271f08aa66c54
DealerPrivMsg to key4 = 09d19a9dffbc9aa924bfb3a4cb4ee910eafb5f1eedda05d3d96365a97df67bd7
DealerPrivMsg to key3 = 438569c7ecca221174704e7de2a79b937aec9314970b32565c262eb719cd151b
log_summary = 21f6dbca8ac23612fc4af4fe40f45f419d4b7d384d98729b045b0c3d150bc941
SignedDealerLog.sig = 708ac8aacbfc8a407ecde0f2c00f8e40458614b72f397fc3b187cd1b4439c8de5000d0c4fe695ac8570c5fbe62c0145cb58a52b671a8741450448359bace590e

Output =
  616b3ee69839819877dc1766879d3ec6551fc4075a02c04868958048c9a55987     # summary = S_round
  00 00000004 03
  8a357a6c64c7d97d2346e8b54603aab0c2e0f5e5fb47f08a165de746cfa4cf61595b62e0968c121b0826fb8eeac97aaa07e0f23692592d3de1a93ba204efb2698672ba1661a5415091791ec2abdb131d6569e39d808c2616dbda7c892c1cb2f7
  8d05407100fccd45f3c61c3cd0f717d3060c188b34ed557ab0931a22f3a7429973c2bfa7726a638e4ea826ee24cc86dc10ac91bf930a3e8715494fedd88129b508a1bf2f330d98ac55f1c78acd2e8bafc783faf30b21efd4476aa4be56d975ad
  9006dcf0757c959a2efc9b467fb9c53162372df58cf9bb18d3509788016ef3ac215a0f31218de24efc5ce5ae588f91f50d3b4ea8f4017906ab0ede7d5e836a88b7ebc3841dc7dd607e1eb5e708bc8369e29a4f1435d4b73b87502c5cad876f69
  03 8a88e3dd…b40f6f5c ca93ac17…dbdabe7c ed4928c6…ac8737d1   # dealers = key1, key4, key3
  04 8139770e…8fc9b394 8a88e3dd…b40f6f5c ca93ac17…dbdabe7c ed4928c6…ac8737d1   # players
  01 ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1   # revealed

Share (key2) = 00 043c89d09d1876c477688c07e323cc4d6534ff13d8be7e92e953d6069d1b4754
Share (key1) = 01 513d422c6104e426b4e6c781a575e99850a2037301ee538d076e7847dae285c2
Share (key4) = 02 2729eb60bcd398667ab1704dcf68f42aebdcdc7474071c0ff22b7d0a8a069a05
Share (key3) = 03 6dddd41403bf8e142f3c367c74409c0fde60d21e2f059019a98ae44caa87841f
```

The output polynomial is the coefficient-wise sum of the commitments of key1, key4 and key3. Each share is the sum of the three private messages the player got from those dealers, revealed ones included. For example, key3's share sums key1's and key4's revealed shares and key3's dealing to itself. key2's dealing contributes to neither. Abbreviated keys refer to the key table.

### 15.4 Vector D: resharing vector C, three of four dealers selected

`round = 1`, `previous` = vector C's output, `dealers = {key2, key1, key4, key3}` (vector C's players), `players = {key5, key2, key1, key3}` (sorted order), Reveal V1. key4 leaves and key5 joins. So `degree = 2`, `required = max(q(4), q(4)) = 3` and `reveal_threshold = 2`. The new evaluation points are key5 → 1, key2 → 2, key1 → 3, key3 → 4.

Each dealer deals its vector C share, so its `commitment[0]` equals `partial_public(C.public, j)` at its vector C index `j` (§7.1). Every player acknowledges every dealer, so no log has a reveal. key1's log never reaches the log collection. The selected dealers are therefore key2, key4 and key3, at previous evaluation points 1, 3 and 4. Their Lagrange weights at 0 (§10) are:

```text
w(key2) = (3·4) / ((3−1)·(4−1)) =  2
w(key4) = (1·4) / ((1−3)·(4−3)) = −2        # r − 2 in F_r
w(key3) = (1·3) / ((1−4)·(3−4)) =  1
```

The blocks have the same layout as in vector C. key1's dealing is omitted because it does not contribute.

```text
S_round = 45e7cf72218b633e117733c506ce4e6c1d7ef8364847160cc8ac88ce510af1be

# dealer key2
DealerPubMsg =
  03
  8c0f5fcc654c76a78fc591159f970eff85daf70a79bda666fbdcaf2d757465498ac3ce4ba25540ceb8353f43863c0c7b012bd4f2e3446b3ada8e86c21a88847ae25c972a225d3b17739c838eaaf78a327c0b8d4bfc2c5e6561ea3d6cc3d6fba7
  a8c44afcf85c9964e5904302f5d49f70fe9efcea1bc1807c1c8b1a6ba50a29daf3fe7209d8f52a53cd75b4a71764ab8507339b181b7c7c38f6c1e1b9d94db09551c2a741b335b4806b0f2adfb79a61498d0439cfdbcd0b9839e209fe80a35c10
  ae73aa6c65f2fdfe5a3690a31899a99e47df86b1ce9bf570d1197b6cc03f2cbf83eff33286b71917bbfa1e57662e8a2406c80ab3fa9e2a2ea54072103e97027772cda3a975875d5a14cca4a960846b2a20b3e49821290217ed07bb87919ab46e
ack_summary = 698686fa363059ac3bf3c04ed047800389a9c1556a8245e84e2488ebb7c35681
DealerPrivMsg to key5 = 2c4598817483bcb2e367101f7f31628ccde0027c48f96eceb7899d4db239f11e
DealerPrivMsg to key2 = 17635a204cc5be54badd5f093f2d56c1c68152f26ef0cf414ca3700051166cf8
DealerPrivMsg to key1 = 398376004f7bf8f2310550cd2cb980f1a2d694794aa2fbe9a8a14e1d79b0bae3
DealerPrivMsg to key3 = 1eb844ce5308ef4312a50d633e3409170f22230ddc1198c8cb8337a62c08dade
log_summary = d243964bae93a2527c580989296520c917c422e9e8ff1fd3139f45bf528cdee7
SignedDealerLog.sig = 4997b52a87a0a5530f628ca9aaa35cde0b3a4a998847c1ce14c06a870f13d786b043d585267ddfb7b8bbde525131b91f1eaca598a670798d5b8c8aefce6a6905

# dealer key4
DealerPubMsg =
  03
  952f6aeefbcd800dd7f8d6a22cac310b4951ccf642125d6fd2aadaaebd9eee247c9172f72d0267d5c7d0dd29fc7f39f510dd237975768bf117f2fdcbfd59f1d467d704e49897181e60b073142cb3e7469822d4cbe2a630cfb657a20263c29de9
  b573030cc86f196c64631c766edfcfb1faae9a9f8e57791e7d800db8a6dfd13caf201ef8ac461384644c9aa8ce6672b40047150a713bd148c205b198ff8ad387c6b8ca1c662b68d58090faff2b42ee0d1e2536c0d24bc59a8caa4d17ed14de39
  9104444428bc7056382ad43c6b11a1a845997720803f0d024d5ce34a57239264d22f7add2f5f82e8af4dcfe9bb593b8a15d6649d4c0b8c2e3c551ff1abfc834fea3df567fa419adf575a5bed71e7f1cba17d9e65c3391b2c78a2c10b053756d3
ack_summary = 78a1c0247a283c5277748b9c15fc517e5b0b54727e255b1bba74ed0995c8b7b3
DealerPrivMsg to key5 = 5e97b13fcc09ef8e32789440596e22a4343dc4fbd2aaf8d97e415c4d9ab4abb8
DealerPrivMsg to key2 = 5529316b062fbe44e4f42c238af975c9426477016e3cf413e5848e7f6c3eac1b
DealerPrivMsg to key1 = 0ade6be26b45048a922437f7640aed9a1650f28546bd0dbf27f5139ffea49b2e
DealerPrivMsg to key3 = 6792af4c4e84bcefa07c67cbf7e63a21577e7f8d5c27fdd94592ebad51e678f3
log_summary = 8293cc5b2057ab627e0e12c46ec266bf4f55b39d75c0523ee8968bf83b355fca
SignedDealerLog.sig = 8956a4fcc8c440669a3530820fa916f2196fc5539320251da66a5af97ac797280296f72c309f41ba6f7a564ff22138c8d32a9e0bce54139aaaa56a2cb9f56004

# dealer key3
DealerPubMsg =
  03
  8452e65fb1fa4a4315acc806af0a0d3dc14f7f090774e7771693c13c4f967e2625b2366382c72bd371f21ad0c024ab520c2703a88ce35c7df4c600a3caac2c34d5432094fb270c60211a15a82c6195414075fc0032f1993a09412843e1f8ddf3
  8f42b2cb6413282e0865a1d0421c1ee62d836f76f156960efa6170d269a998c0b258a984d285f9a0cd0e07c0168096b504f2ddeaeab25e6bff98b36a171d430f252df71cc4f05acbdcfaf2a638b148a819da59a2b385e0d1d018820124f24954
  b6fc5a90f92fec5aaa4fbaaab86480777d7bef760bc63fea31ad2512e24be7668767717e43dfb4e6046d59dadb1e726213c071ecaa170d4aef622bf1488f9f6da507f83a9980376fc59d5314b703c258c23b3f69a49d9acc498bb7d8c63e104b
ack_summary = f6fc303bb8cf216a6b0c98b9bc9cab1d424bcd1b36cbf3ddf488adba60c9b38a
DealerPrivMsg to key5 = 3301305dedc5a604e3297c275643d09f7fa804374701c79720fbf6727c919572
DealerPrivMsg to key2 = 511f3508f4d86e09ca14deb44d15a069eea4b3c3dea914b816b22afab15ce50e
DealerPrivMsg to key1 = 544a3ac1ef5a68dab0c4861b4f143369d7993cc0f5fd1b7d8aad81e648e972f2
DealerPrivMsg to key3 = 3c824188dd4b96779738725c5c3f899f3a859f2e8cfddbe77cedfb3543373f1e
log_summary = db36a76f6d42d02ffa2bd2265afcb14bf4416d4f4b029d7109134a6efe170248
SignedDealerLog.sig = c52b44940cf7afe24408e026605df83eeb83e829e16c37a8cd1923367325047f22602fb211dbc0a0c3ff5e3b087b495fa97049b73dd5ee9b2f9f48332181870c

Output =
  45e7cf72218b633e117733c506ce4e6c1d7ef8364847160cc8ac88ce510af1be     # summary = S_round
  00 00000004 03
  8a357a6c64c7d97d2346e8b54603aab0c2e0f5e5fb47f08a165de746cfa4cf61595b62e0968c121b0826fb8eeac97aaa07e0f23692592d3de1a93ba204efb2698672ba1661a5415091791ec2abdb131d6569e39d808c2616dbda7c892c1cb2f7
  b6cc482e559fa44baa51e553897b009129e71763fdbd085a9a3855912dbb9417f4333184e51055f2ba7cce3f04548d1b16ed24ec271e6371d6dac77434e5ab217c9d4658a7968a1dd84304659ad5d0f1eada3f54505f1db151975b789e8979b2
  8c691fe5377e06b411e70e856946a26422dc5fc6238c81ff1828bd8ecc38c6e85af6c2c61ccbde8573ddbd78a60001970a26d00d77bc52f765a5bf8c09f12bea3bdfe150125f1b466db3069f848e051543291f678d0bcd526c0caeef5eb5a3c8
  03 8139770e…8fc9b394 ca93ac17…dbdabe7c ed4928c6…ac8737d1   # dealers = key2, key4, key3
  04 6e7a1cdd…80505bf1 8139770e…8fc9b394 8a88e3dd…b40f6f5c ed4928c6…ac8737d1   # players
  00    # revealed

Share (key5) = 00 424aa6346856bd9678404bedab6c287606aa233b339d0f80938c7871ab9c203f
Share (key2) = 01 49812dc6aba1eb71a9211c87bf1f3a604a9c0fa8e00f2711e4efedfb7b0c66c9
Share (key1) = 02 3da6a7aa8e2ad461bb4cdfbed6cf82139ce6dca5fdca9bd38c05f6e23f01b25b
Share (key3) = 03 1ebb13e00ff17866aec39592f27cff8ffd8a8a328ccf6dc588ce9325f77c02f5
```

The output polynomial is `2·C_key2 − 2·C_key4 + C_key3`, coefficient by coefficient. Its constant term equals vector C's group key. Each share is `2·s_key2 − 2·s_key4 + s_key3` in `F_r`, where `s_d` is the player's private message from dealer `d`.

Vectors C and D were also reproduced independently of the library, with a separate BLS12-381 implementation and plain arithmetic mod `r`. That check decoded every commitment, verified every private message against it, and interpolated each dealer's secret from its private messages. It recomputed both output polynomials (the sum for C, the weighted combination for D) and every share from the private messages. It confirmed `share · g == partial_public(output.public, index)` for each player, and that the weighted vector C shares of key2, key4 and key3 give vector C's group secret. It verified every ack and log signature over `0x00 ‖ ack_summary` and `0x00 ‖ log_summary`.
