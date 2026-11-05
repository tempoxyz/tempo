# Commonware cryptography

This chapter specifies the cryptographic primitives that Tempo's consensus, DKG and validator networking use, as implemented by commonware 2026.9.0: Ed25519 identities and signatures, BLS12-381 signatures in the MinSig variant, threshold BLS (shares, public polynomials, partial signatures and recovery), the threshold VRF signing scheme that Simplex runs with, and the BLAKE3 transcript that the DKG and the p2p handshake build on.

It specifies only the parts and configurations Tempo uses, but specifies them completely: byte encodings, every check a decoder performs, signed messages, and the algorithms. Where an external standard defines a construction, this chapter cites it and states the parameters.

Related chapters: byte-level notation and the generic codec in [codec.md](codec.md); the DKG in [dkg.md](dkg.md); Simplex messages, certificates and leader election in [simplex.md](simplex.md); the transport in [p2p.md](p2p.md); Tempo's use of all of these in [../07-consensus.md](../07-consensus.md) and [../08-p2p-and-sync.md](../08-p2p-and-sync.md).

## 1. Scope and notation

The notation of [codec.md](codec.md#2-notation) applies. In particular:

- `varint(x)` is the unsigned LEB128 encoding of [codec.md §3](codec.md#3-varint).
- `u32be(x)` is a 4-byte big-endian integer ([codec.md §4](codec.md#4-fixed-width-integers)).
- `‖` is byte concatenation and `b"…"` is an ASCII byte string.
- A participant index is a `u32`, encoded as `varint` ([codec.md §9.2](codec.md#92-participant-index)).

"Decoding" a fixed-size object reads exactly its size from the input. Whether trailing bytes are allowed is decided by the enclosing structure ([codec.md §11](codec.md#11-decoding-rules)).

What Tempo uses:

| Primitive | Where | Section |
|---|---|---|
| Ed25519 | validator identities, p2p authentication, DKG dealer logs and acks, ValidatorConfigV2 key-ownership signatures, header `consensus_context.proposer` | §3 |
| BLS12-381 MinSig | network identity, Simplex votes and certificates | §4 |
| Threshold BLS, `NonZeroCounter` mode | per-epoch public polynomial and shares | §5 |
| Threshold VRF scheme | Simplex votes, certificates and seeds | §6 |
| Transcript (BLAKE3) | DKG round summaries and dealer-log signatures, p2p handshake | §7 |

Tempo does not use the MinPk variant, the `RootsOfUnity` sharing mode, BLS proofs of possession, plain (non-threshold) BLS multisignatures, timelock encryption or secp256r1.

## 2. Namespaced messages

Every signature in this chapter signs a byte string built from a **namespace** and a **message** with `union_unique(ns, msg)`. That function and `union(a, b)` are defined, with vectors, in [codec.md §7.2](codec.md#72-union_unique) and [codec.md §7.1](codec.md#71-union). `union_unique` makes `(ns, msg)` pairs collision-free; `union` is used only to derive one namespace from another (for example `union(b"TEMPO", b"_SEED") = b"TEMPO_SEED"`).

Signing `msg` "under namespace `ns`" always means signing the payload `union_unique(ns, msg)`, for Ed25519 (§3.5) and for BLS (§4.5) alike. An empty namespace still contributes its length byte: `union_unique(b"", m) = 0x00 ‖ m`.

## 3. Ed25519

Tempo uses Ed25519 as defined in [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (the pure variant, no context, no prehash) for signing, and the [ZIP-215](https://zips.z.cash/zip-0215) rules for verification.

### 3.1 Ed25519 encodings

| Object | Size | Encoding | Decoder checks |
|---|---|---|---|
| Private key | 32 bytes | the RFC 8032 seed `k` | none: any 32 bytes are a valid private key |
| Public key | 32 bytes | the RFC 8032 point encoding of `A` (little-endian `y`, sign of `x` in the top bit of byte 31) | MUST decompress under §3.2 |
| Signature | 64 bytes | `R_bytes[32] ‖ s_bytes[32]` | none at decode time: any 64 bytes decode; §3.4 checks them |

A public key keeps the exact 32 bytes it was decoded from. It is re-encoded as those bytes, compared as those bytes, and hashed as those bytes in §3.4. Two different byte strings that decompress to the same point (a non-canonical encoding and its canonical form) are two different public keys.

**Ordering.** Public keys are ordered by lexicographic comparison of their 32 bytes. Every ordered set of Ed25519 keys (participants, dealers, players; [codec.md §6.1](codec.md#61-ordered-set)) uses this order, and a participant's index is its position in the set.

### 3.2 Public key decoding

```python
def ed25519_decompress(b: bytes32) -> Point | None:
    sign = b[31] >> 7
    y = int.from_bytes(b, "little") & (2**255 - 1)
    y = y % p                                   # p = 2**255 - 19; y >= p is accepted (non-canonical)
    u = y*y - 1
    v = d*y*y + 1                               # d = -121665/121666 mod p
    x = sqrt_ratio(u, v)                        # the non-negative (even) root of u/v, or None
    if x is None:
        return None                             # not on the curve: reject
    if sign == 1:
        x = (-x) % p                            # also applied when x == 0 (accepted)
    return (x, y)
```

A 32-byte string is a valid public key iff `ed25519_decompress` returns a point. No other check applies: non-canonical `y` (in `[p, 2^255)`), the encoding of `x = 0` with the sign bit set, small-order points and points outside the prime-order subgroup are all accepted, as ZIP-215 requires.

This is the rule for every place that "decodes an Ed25519 public key": p2p peer identities, participant sets, `consensus_context.proposer` ([../02-encoding.md](../02-encoding.md)), and ValidatorConfigV2 `publicKey` fields ([../precompiles/validator-config-and-zones.md](../precompiles/validator-config-and-zones.md)).

### 3.3 Ed25519 signing

Signing is RFC 8032 §5.1.6 Ed25519 with the seed `k` as the private key:

```python
def ed25519_sign(k: bytes32, M: bytes) -> bytes64:
    h = sha512(k)
    a = clamp(h[0:32]) mod L                    # clamp: h[0] &= 248; h[31] &= 127; h[31] |= 64
    prefix = h[32:64]
    A = encode([a]B)
    r = int.from_bytes(sha512(prefix ‖ M), "little") mod L
    R = encode([r]B)
    k_ = int.from_bytes(sha512(R ‖ A ‖ M), "little") mod L
    s = (r + k_ * a) mod L
    return R ‖ s.to_bytes(32, "little")
```

`L = 2^252 + 27742317777372353535851937790883648493` is the order of the base point `B`. Reducing the clamped scalar mod `L` does not change `A` or `s`, so the output is byte-identical to RFC 8032. Signing is deterministic.

### 3.4 Ed25519 verification

Verification of signature `R_bytes ‖ s_bytes` on payload `M` under public key bytes `A_bytes` (ZIP-215):

```python
def ed25519_verify(A_bytes: bytes32, M: bytes, sig: bytes64) -> bool:
    A = ed25519_decompress(A_bytes)             # already checked when the key was decoded
    R_bytes, s_bytes = sig[0:32], sig[32:64]
    s = int.from_bytes(s_bytes, "little")
    if s >= L:
        return False                            # s MUST be canonical
    R = ed25519_decompress(R_bytes)
    if R is None:
        return False                            # non-canonical R encodings are accepted
    k = int.from_bytes(sha512(R_bytes ‖ A_bytes ‖ M), "little") mod L   # the bytes as received
    return [8]([s]B - R - [k]A) == identity     # cofactored equation
```

An implementation MUST use the cofactored equation `[8][s]B = [8]R + [8][k]A` and MUST NOT use the cofactorless equation `[s]B = R + [k]A`. The challenge `k` MUST hash `R_bytes` and `A_bytes` exactly as received, not re-encoded. Libraries that implement RFC 8032's strict checks (canonical `A` and `R`, rejection of small-order points, cofactorless equation) do not accept the same signatures and MUST NOT be used for consensus.

### 3.5 Namespaced Ed25519 signatures

```python
def sign(k, ns: bytes, msg: bytes) -> bytes64:           return ed25519_sign(k, union_unique(ns, msg))
def verify(A_bytes, ns: bytes, msg: bytes, sig) -> bool:  return ed25519_verify(A_bytes, union_unique(ns, msg), sig)
```

Every Ed25519 signature Tempo produces or checks goes through these two functions:

| Use | Namespace `ns` | Message `msg` | Specified in |
|---|---|---|---|
| ValidatorConfigV2 `addValidator` | `b"TEMPO_VALIDATOR_CONFIG_V2_ADD_VALIDATOR"` | 32-byte keccak256 preimage hash | [../precompiles/validator-config-and-zones.md](../precompiles/validator-config-and-zones.md) |
| ValidatorConfigV2 `rotateValidator` | `b"TEMPO_VALIDATOR_CONFIG_V2_ROTATE_VALIDATOR"` | 32-byte keccak256 preimage hash | same |
| Transcript summaries (DKG dealer logs and acks, p2p handshake) | `b""` | the 32-byte transcript summary | §7.4, [dkg.md](dkg.md), [p2p.md](p2p.md) |

### 3.6 Ed25519 batch verification

The DKG verifies sets of dealer-log and acknowledgement signatures as a batch. A batch is a list of `(A_bytes, ns, msg, sig)` entries. Its result is:

- **invalid** if the list is empty;
- otherwise **valid** iff every entry passes §3.5 `verify`, except with probability at most about `2^-128` per batch.

The reference implementation checks one random linear combination of the cofactored equations:

```text
[8]( [-Σ z_i·s_i]B + Σ [z_i]R_i + Σ [z_i·k_i]A_i ) == identity
```

with independent uniformly random 128-bit `z_i`, and the same per-entry checks as §3.4 (`s_i < L`, `R_i` decompresses, `k_i` over the received bytes). Because ZIP-215 verification is cofactored, a batch accepts exactly the signatures that individual verification accepts. An implementation MAY verify the entries one by one instead. The random coefficients are local: they MUST be unpredictable to whoever supplied the signatures, and they never appear on the wire.

### 3.7 Ed25519 test vector

| Item | Hex |
|---|---|
| seed `k` | `0101010101010101010101010101010101010101010101010101010101010101` |
| public key | `8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c` |
| `union_unique(b"TEMPO", b"hello")` | `0554454d504f68656c6c6f` |
| `sign(k, b"TEMPO", b"hello")` | `e4ea405f3b0a398aa179cbd93e3a32bd4417f47d05ad56e699856d0855a4676c4ef479c2a8aac549722e55c9b5955702010077fb0c7592d1cc4afd3109b3e105` |

The signature equals plain RFC 8032 Ed25519 over the 11-byte payload.

## 4. BLS12-381

### 4.1 Curve parameters

BLS12-381 is the pairing-friendly curve of [draft-irtf-cfrg-pairing-friendly-curves](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11) §4.2.1:

| Name | Value |
|---|---|
| base field modulus `p` | `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` |
| group order `r` | `0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001` |
| G1 | `y² = x³ + 4` over `Fp`, prime-order subgroup of order `r` |
| G2 | `y² = x³ + 4(u + 1)` over `Fp2 = Fp[u]/(u² + 1)`, prime-order subgroup of order `r` |
| `g1` (compressed) | `97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb` |
| `g2` (compressed) | `93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8` |
| pairing | the optimal ate pairing `e: G1 × G2 → GT` |

Tempo uses the **MinSig** variant: signatures and message hashes are in G1 (48 bytes), public keys are in G2 (96 bytes).

### 4.2 Scalar encoding

A scalar is an element of `Fr` (integers mod `r`), encoded as 32 bytes, big-endian.

```python
def decode_scalar(b: bytes32, allow_zero: bool) -> int:
    x = int.from_bytes(b, "big")
    require(x < r)                       # non-canonical encodings are rejected
    if not allow_zero:
        require(x != 0)
    return x
```

A **private key** (a BLS secret or a share's secret) is a scalar decoded with `allow_zero = False`. The encoder always writes the canonical value, so its first byte is at most `0x73`.

### 4.3 Point encoding and decoding

G1 and G2 points use the compressed form of the Zcash BLS12-381 serialization ([draft-irtf-cfrg-pairing-friendly-curves Appendix C](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-pairing-friendly-curves-11#appendix-C)):

| Group | Size | Layout |
|---|---|---|
| G1 | 48 bytes | `x` as 48-byte big-endian `Fp`, with flags in the top 3 bits of byte 0 |
| G2 | 96 bytes | `x = x0 + x1·u` as `x1[48] ‖ x0[48]` (big-endian each; **`x1` first**), with flags in the top 3 bits of byte 0 |

Flags in byte 0: bit 7 (`0x80`) **compression**, bit 6 (`0x40`) **infinity**, bit 5 (`0x20`) **sign**. For a finite point the sign bit is 1 iff `y` is the lexicographically larger of `±y`: for G1, `y > (p−1)/2`; for G2, with `y = y0 + y1·u`, `y1 > (p−1)/2` if `y1 ≠ 0`, else `y0 > (p−1)/2`.

The encoder writes `0x80 | sign·0x20` in the top bits with `x`. It never encodes the point at infinity in any structure Tempo transmits, because every decoder rejects it.

Decoding, for both groups (`n = 48` for G1, `96` for G2):

```python
def decode_point(b: bytes[n], group) -> Point:
    if b[0] & 0x80 == 0:
        reject("bad encoding")                    # uncompressed form is not accepted
    if b[0] & 0x40:
        reject("infinity")                        # whether or not the remaining bits are zero
    x_bytes = clear_top_3_bits(b)
    x = parse_fp(x_bytes) if group == G1 else Fp2(c1=parse_fp(x_bytes[0:48]), c0=parse_fp(x_bytes[48:96]))
    # parse_fp rejects ("bad encoding") any 48-byte big-endian value >= p
    y = sqrt(x**3 + B)                            # B = 4 (G1) or 4(u+1) (G2)
    if y is None:
        reject("not on curve")
    if lexicographically_largest(y) != bool(b[0] & 0x20):
        y = -y
    P = (x, y)
    if group == G1 and x == 0:
        reject("not in group")                    # (0, ±2) is on the curve but has order 3
    if not in_subgroup(P, group):                 # [r]P == identity
        reject("not in group")
    return P
```

So a decoded G1 or G2 point is always finite, on the curve, and in the order-`r` subgroup. Every 48-byte signature and 96-byte public key in this chapter is decoded this way, except where §6.2 defers the check.

### 4.4 Hash to curve

Messages are hashed to G1 with the [RFC 9380](https://www.rfc-editor.org/rfc/rfc9380) suite `BLS12381G1_XMD:SHA-256_SSWU_RO_` (`hash_to_curve`, random-oracle variant, `expand_message_xmd` with SHA-256), using the domain separation tag

```text
DST_MESSAGE = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"      # 43 bytes
```

which is the proof-of-possession ciphersuite tag of the [IETF BLS signature draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#section-4.2.3) for MinSig. The namespace is not part of the DST; it is prepended to the message:

```text
H(ns, msg) = hash_to_curve_G1(union_unique(ns, msg), DST_MESSAGE)
```

The result is always in the order-`r` subgroup (RFC 9380 clears the cofactor).

### 4.5 MinSig signing and verification

```python
def bls_public(sk: Scalar) -> G2:                      return sk * g2
def bls_sign(sk: Scalar, ns: bytes, msg: bytes) -> G1: return sk * H(ns, msg)

def bls_verify(pk: G2, ns: bytes, msg: bytes, sig: G1) -> bool:
    if sig == identity:
        return False                                   # rejected even though e(pk, O) == e(g2, O)
    return e(H(ns, msg), pk) == e(sig, g2)             # equivalently e(H, pk) · e(sig, -g2) == 1
```

`pk` and `sig` are points that passed §4.3. This is the `CoreSign`/`CoreVerify` of the IETF BLS draft over the payload `union_unique(ns, msg)`. Signing is deterministic, so a key has exactly one valid signature per `(ns, msg)`.

Test vector (`sk = 42`, `ns = b"TEMPO_SEED"`, `msg = 0x0102`, the encoding of round `(epoch 1, view 2)`):

| Item | Hex |
|---|---|
| `sk` (32 bytes) | `000000000000000000000000000000000000000000000000000000000000002a` |
| `pk = sk·g2` | `ac7fa63dfc38bbf3712e27a180391bca4ccabf609c5967a0592eff420b6235f3f2b323051cb099acc3969aca310f7ff4191b2d6db43fafc2c9592f7e5f73981107975d3d92b843891e724dbc9f05b5eee5a3b2b1fc782ede8149f30830b84444` |
| `union_unique(ns, msg)` | `0a54454d504f5f534545440102` |
| `H(ns, msg)` | `90add0c9a8a48b67d8e79a9673e91363e6a06140e6f64eb285849ad1f094ef0074e8345470c4b1383f87559fccd3e368` |
| `bls_sign(sk, ns, msg)` | `b029e43f5524e36425d07c9806d0897b598c40cf8954cfdbeb9c867ba2127f727c86031e9d2d70a27130a5879e55cbf6` |

### 4.6 Batch verification

Two batch forms are used. Both are probabilistic shortcuts for checking each signature individually with §4.5, and an implementation MAY replace either with individual checks. Their random coefficients are local, MUST be unpredictable to the senders, and never appear on the wire.

**Same signer, several messages** (`batch_same_signer(pk, [(ns_i, msg_i, sig_i)])`), used for the two signatures of a vote or certificate (§6):

```python
def batch_same_signer(pk, entries) -> bool:
    assert len(entries) >= 1
    z = [random_u128() for _ in entries]               # uniform in [0, 2**128), zero allowed
    hm  = Σ z_i * H(ns_i, msg_i)
    sig = Σ z_i * sig_i
    return bls_verify_prehashed(pk, hm, sig)           # sig != identity and e(hm, pk) == e(sig, g2)
```

**Same message, several signers** (`batch_same_message(ns, msg, [(pk_i, sig_i)])`), used to check many votes for one subject (§6.4):

```python
def batch_same_message(ns, msg, entries) -> set[int]:      # returns the indices of invalid entries
    z = [random_u128() for _ in entries]
    if bls_verify_prehashed(Σ z_i·pk_i, H(ns, msg), Σ z_i·sig_i):
        return {}
    return bisect(entries, z)                          # recursively re-check halves to find the bad entries
```

Result semantics: with probability at least `1 − 2^-128`, `batch_same_signer` returns true iff every entry verifies individually, and `batch_same_message` returns exactly the entries that fail individual verification. (The weighted-sum signature can be the identity only with negligible probability; the reference implementation then reports failure.)

### 4.7 Proof of possession

Tempo does not create or check BLS proofs of possession. Its public keys are never aggregated across independent signers: the only combination is threshold recovery (§5.7) under one public polynomial produced by the DKG. For reference, the unused tag is `b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"`.

## 5. Threshold BLS

A secret `s` is shared with a polynomial `f(X) = a_0 + a_1·X + … + a_{t−1}·X^{t−1}` over `Fr` with `f(0) = a_0 = s`. Participant `i` holds `f(x_i)`. Any `t` shares determine `s`, and any `t` partial signatures determine the signature under `s` ([Shamir](https://dl.acm.org/doi/10.1145/359168.359176), [Boldyreva 2003](https://doi.org/10.1007/3-540-36288-6_3)).

### 5.1 Participant indices

Participants of an epoch are an ordered set of `n` Ed25519 public keys (§3.1). Participant `i` (0-based position in the set) is identified on the wire by the `u32` index `i`, encoded as `varint` ([codec.md §9.2](codec.md#92-participant-index)). An index `i ≥ n` names no participant; every operation below that takes an index rejects it.

### 5.2 Share encoding

```text
Share = varint(index:u32) ‖ secret[32]
```

`secret` is a private-key scalar (§4.2): it MUST be `< r` and MUST NOT be zero. The decoder does not check the index against any participant count; §5.5 does that when the share is used.

A share's **public share** is `secret · g2`. A share is *consistent* with a public polynomial iff its public share equals the partial public key of its index (§5.5). Tempo uses a share for an epoch only if it is consistent with that epoch's public polynomial ([../07-consensus.md](../07-consensus.md) §9.5, §14). Example (§5.8): index 1 with secret 81 encodes as `01` followed by the 32-byte big-endian 81.

### 5.3 Evaluation points (mode)

The **mode** maps participant indices to evaluation points:

| Mode | Tag | Evaluation point of index `i` (`0 ≤ i < n`) | Tempo |
|---|---|---|---|
| `NonZeroCounter` | `0x00` | `x_i = i + 1` | used |
| `RootsOfUnity` | `0x01` | `ω^i`, `ω` a primitive `next_pow2(n)`-th root of unity | never accepted |

Tempo decodes every sharing with **mode version 0**, which accepts only tag `0x00`. Tag `0x01` is rejected as unsupported, and any other tag is an invalid enum value. Everything below assumes `x_i = i + 1`; the point `0` is never assigned, because `f(0)` is the secret.

### 5.4 Public polynomial and Sharing encoding

The **public polynomial** commits to `f` coefficient-wise: `F(X) = A_0 + A_1·X + … + A_{t−1}·X^{t−1}` with `A_j = a_j · g2`. A polynomial is encoded as its coefficients, constant term first:

```text
Poly<K>  = varint(k) ‖ coeff_0 ‖ coeff_1 ‖ … ‖ coeff_{k−1}        # k ≥ 1; K = G2 (96 bytes) or Fr (32 bytes)
```

A **Sharing** is the public output of a secret sharing:

```text
Sharing = mode:u8 ‖ u32be(total) ‖ Poly<G2>
```

Note that `total` is a fixed 4-byte big-endian integer, not a varint. Decoding with configuration `(max_participants M, mode version)`, which Tempo sets to `(65535, 0)`:

```python
def decode_sharing(buf, M=65535) -> Sharing:
    mode = read_u8(buf)
    require(mode == 0x00)                  # 0x01: unsupported under mode version 0; others: invalid enum
    total = read_u32be(buf)
    require(1 <= total <= M)
    k = read_varint(buf)                   # canonical LEB128, codec.md §3.2
    require(1 <= k <= M)
    coeffs = [decode_point(read(buf, 96), G2) for _ in range(k)]   # §4.3: finite, on curve, in subgroup
    return Sharing(mode, total, coeffs)
```

The decoder does not relate `k` to `total`. Because no decoded coefficient can be the identity, a decoded sharing's **threshold** is `required = k` (in general, one more than the exact degree, ignoring leading zero coefficients).

Derived values:

- **Identity** (group public key, "network identity"): `public = A_0`, the constant term. It equals `s · g2`.
- **Partial public key** of index `i`: §5.5.

Tempo's Simplex scheme (§6) additionally requires `total == n` (the number of participants) and `required == q`, the quorum of [codec.md §8](codec.md#8-fault-model-n3f1). The reference implementation aborts when an epoch's sharing violates either; the DKG ([dkg.md](dkg.md)) only produces sharings that satisfy them.

The DKG also uses `Poly<Fr>` (a dealer's secret polynomial) and evaluates polynomials at points; evaluation is Horner's rule or any equivalent:

```python
def eval_poly(coeffs, x):              # coeffs in Fr or G2, x in Fr
    acc = coeffs[-1]
    for c in reversed(coeffs[:-1]):
        acc = acc * x + c
    return acc
```

### 5.5 Partial public keys

```python
def partial_public(S: Sharing, i: int) -> G2:
    require(0 <= i < S.total)          # else: invalid index
    return eval_poly(S.coeffs, i + 1)  # = f(i+1) · g2
```

A partial public key may in principle be the identity; it is used as computed, without a check.

### 5.6 Partial signatures

The partial signature of share `(i, s_i)` on `(ns, msg)` is `σ_i = bls_sign(s_i, ns, msg) = s_i · H(ns, msg)` (§4.5), tagged with `i`. Its standalone encoding is

```text
PartialSignature = varint(index:u32) ‖ value[48]           # value: G1, decoded per §4.3
```

and it is valid iff `bls_verify(partial_public(S, i), ns, msg, σ_i)` holds; an index `≥ total` makes it invalid. In Simplex votes the index and the signatures are carried in the attestation form of §6.1 instead.

### 5.7 Signature recovery

Recovery combines partial signatures by Lagrange interpolation in the exponent at `X = 0`:

```python
def recover(S: Sharing, partials: list[(int, G1)]) -> G1:
    t = S.required
    # Sort by index (stable) and keep the first entry of each index.
    evals = dedup_by_index(sorted(partials, key=index))
    evals = evals[:t]                                  # the t lowest indices
    require(len(evals) == t)                           # else: not enough partial signatures
    require(all(i < S.total for i, _ in evals))        # else: invalid index
    xs = [i + 1 for i, _ in evals]
    sig = identity
    for (i, sigma_i), x_i in zip(evals, xs):
        lam = Π_{x_j in xs, x_j != x_i} x_j / (x_j - x_i)      # in Fr
        sig += lam * sigma_i
    return sig
```

`recover` does not verify its inputs; callers verify each partial first (§6.4). If the `t` inputs are valid partial signatures on the same `(ns, msg)` under `S`, the result is `s · H(ns, msg)`, the unique valid signature under the identity `A_0`, whatever subset of `t` valid partials was used. Therefore every honest node recovers byte-identical certificates.

### 5.8 Threshold test vectors

`f(X) = 7 + 11X + 13X²`, `n = 4`, mode `NonZeroCounter`, `ns = b"TEMPO_SEED"`, `msg = 0x0102`. The shares are `f(1..4) = 31, 81, 157, 259`.

`Sharing` (`00` mode ‖ `00000004` total ‖ `03` coefficient count ‖ `7·g2 ‖ 11·g2 ‖ 13·g2`):

```text
0000000004038d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3ca190be857d602284393305bfe0a29e29a6982ed3f04ccaabafb7e59cdc7eda85c22bc3e8690355c7a0fb7590ae40f1b009303f04d568e289a35102b6df883d5ed620355c0eb5d02236718cdaf99fba6e19ef5cee2996268eb9a53ae1ee09bce38bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c
```

| Index | `Share` encoding | `PartialSignature` encoding |
|---|---|---|
| 0 | `00` ‖ `00…001f` | `0088bb0497aeb2e0c41343167a428759823d7d42fc437e9e6e865851f850ef418cf203dc1e1d3de4f553994ae2fe198082` |
| 1 | `01` ‖ `00…0051` | `018b28c64e6c8f71d92be34983090d1e15b154f0de2b2c4219178bbc21334e04034b56ec0ae2ed457269570a325aaddb54` |
| 2 | `02` ‖ `00…009d` | `02acb9b38f8725b7e4bd5e1e03c792eb4dc33be37a50b0dca45b6800e28e64819a3138e50c7aa1845b70236a8fd548df9b` |
| 3 | `03` ‖ `00…0103` | `03a4131ed795fc020b3c7251f40493fe93f9a45a2cd3a17480d53eeddb2b8f85d59a90ee4e974a11aaa5664b54e54877b7` |

(`00…001f` is the 32-byte big-endian scalar.) Partial public key of index 0 is `a73770d14fe028d8d821c1c6b357ccebc8d28b24abd941e9f13628bb65aea48c33a11f24c842e819db9c6b98726f1b630924dc101eeb2cc39ceaca84826b79954842ce35aff65ae5e60e396b7dc20bfc77670c9798bf89181f0f02a09f6b481c`.

Recovering from indices 1, 2, 3 gives `908b6563cee2e15292d85743d54e3e9df8126620c5a78c91a4665a82b0693a25879160ca46a11e7da05494e42f8b22b3`, which equals `bls_sign(7, ns, msg)` and verifies under the identity `8d0273f6…8d3c` (the first coefficient above).

## 6. Threshold VRF scheme

Simplex in Tempo signs with the threshold VRF scheme over MinSig. Each vote carries two partial signatures from the voter's share, and each certificate carries the two recovered threshold signatures: a **vote signature** over the vote's subject and a **seed signature** over the round. The seed signature is a threshold BLS signature, hence unique and unpredictable before `t` participants sign: it is the per-round randomness (the "VRF output") that leader election uses ([simplex.md](simplex.md)).

### 6.1 Vote signature pair

```text
VrfSignature = vote_signature[48] ‖ seed_signature[48]      # 96 bytes, both G1
Attestation  = varint(signer:u32) ‖ VrfSignature             # a vote's signature part
```

`signer` is the voter's participant index (§5.1). In a vote the two values are partial signatures under the voter's share. How an `Attestation` is framed inside `Notarize`, `Nullify` and `Finalize` messages is in [simplex.md](simplex.md).

### 6.2 Certificate signature pair

```text
VrfCertificate = vote_signature[48] ‖ seed_signature[48]    # 96 bytes, both G1, recovered
```

The two fields are the recovered threshold signatures (§5.7). A certificate carries no signer list.

**Deferred point checks.** A `VrfSignature` inside an `Attestation`, and a `VrfCertificate`, are deferred fields of 96 bytes ([codec.md §5.7](codec.md#57-deferred-fixed-size-fields)): the decoder reads exactly 96 raw bytes and fails only if fewer remain. The §4.3 checks on the two G1 points run when the signature is first used. A pair whose bytes fail §4.3 makes the vote or certificate **invalid** at verification (§6.4, §6.5), rather than making the enclosing message undecodable. An implementation MAY decode the points eagerly, provided it treats a failure as "invalid signature" for the purpose of the enclosing protocol, not as a framing error: for example, a message holding a certificate with an invalid point is still consumed with the same length.

### 6.3 Signing a subject

With epoch namespace `NS` (`b"TEMPO"` in Tempo), the scheme derives four namespaces:

| Name | Value | Tempo |
|---|---|---|
| `ns_notarize` | `union(NS, b"_NOTARIZE")` | `b"TEMPO_NOTARIZE"` |
| `ns_nullify` | `union(NS, b"_NULLIFY")` | `b"TEMPO_NULLIFY"` |
| `ns_finalize` | `union(NS, b"_FINALIZE")` | `b"TEMPO_FINALIZE"` |
| `ns_seed` | `union(NS, b"_SEED")` | `b"TEMPO_SEED"` |

A **subject** is what a vote or certificate is about. Its vote namespace, vote message and seed message are:

| Subject | Vote namespace | Vote message | Seed message |
|---|---|---|---|
| `Notarize { proposal }` | `ns_notarize` | `encode(proposal)` | `encode(proposal.round)` |
| `Nullify { round }` | `ns_nullify` | `encode(round)` | `encode(round)` |
| `Finalize { proposal }` | `ns_finalize` | `encode(proposal)` | `encode(proposal.round)` |

`encode(Round)` is `varint(epoch) ‖ varint(view)` ([codec.md §9.1](codec.md#91-epoch-view-height-and-round)) and `encode(Proposal)` is defined in [simplex.md §3.3](simplex.md#33-proposal). The seed message depends only on the round, so all three subjects of one round share one seed signature.

```python
def sign_vote(share, subject) -> Attestation:
    vote = bls_sign(share.secret, subject.vote_ns, subject.vote_msg)
    seed = bls_sign(share.secret, ns_seed, subject.seed_msg)
    return Attestation(signer=share.index, signature=VrfSignature(vote, seed))
```

A node signs only if it holds a share consistent with the epoch's sharing (§5.2). Otherwise it is a verifier and produces no votes.

### 6.4 Verifying a vote

```python
def verify_attestation(S: Sharing, subject, a: Attestation) -> bool:
    if a.signer >= S.total:
        return False
    if not points_decode(a.signature):             # §6.2
        return False
    pk_i = partial_public(S, a.signer)
    return (bls_verify(pk_i, subject.vote_ns, subject.vote_msg, a.signature.vote_signature)
        and bls_verify(pk_i, ns_seed, subject.seed_msg, a.signature.seed_signature))
```

A vote is valid iff both partial signatures verify. The reference implementation checks one vote with `batch_same_signer` over the two entries, and checks many votes for one subject with `batch_same_message` (once for the vote signatures, once for the seed signatures), marking a signer invalid if either of its two partials fails (§4.6). These give the same verdicts as the function above.

### 6.5 Verifying certificates

A certificate is checked against the epoch's identity `A_0` only; no participant set or partial public key is needed. This is how followers verify finalizations ([../07-consensus.md](../07-consensus.md) §7).

```python
def verify_certificate(identity: G2, subject, c: VrfCertificate) -> bool:
    if not points_decode(c):                       # §6.2
        return False
    return (bls_verify(identity, subject.vote_ns, subject.vote_msg, c.vote_signature)
        and bls_verify(identity, ns_seed, subject.seed_msg, c.seed_signature))
```

The reference implementation evaluates this as `batch_same_signer(identity, [(vote_ns, vote_msg, vote_sig), (ns_seed, seed_msg, seed_sig)])`.

When it verifies several certificates at once, it also requires that certificates for the same round carry the same seed signature, returning false for the whole set otherwise, and then batch-verifies every vote signature plus one seed signature per round. Because a round has exactly one valid seed signature, this accepts a set iff every certificate in it passes `verify_certificate`.

### 6.6 Assembling a certificate

```python
def assemble(S: Sharing, attestations: list[Attestation]) -> VrfCertificate:
    idx = [a.signer for a in attestations]
    require(all(i < S.total for i in idx))          # unknown signer
    require(len(set(idx)) == len(idx))              # duplicate signer
    require(len(idx) >= S.required)                 # insufficient attestations
    vote = recover(S, [(a.signer, a.signature.vote_signature) for a in attestations])
    seed = recover(S, [(a.signer, a.signature.seed_signature) for a in attestations])
    return VrfCertificate(vote, seed)
```

The inputs MUST be attestations that passed §6.4 for the same subject. Both recoveries use the same `S.required` lowest indices. With Tempo's sharings `S.required = q`, so a certificate needs `q` valid votes ([../07-consensus.md](../07-consensus.md) §5.2).

### 6.7 Seed

The **seed** of round `ρ` is `(ρ, seed_signature)`: the round and the 48-byte recovered seed signature taken from any notarization, nullification or finalization of that round. Its encoding, where one is needed, is `encode(Round) ‖ seed_signature[48]`. It is valid iff `bls_verify(identity, ns_seed, encode(ρ), seed_signature)`.

The seed is uniquely determined by the round and the epoch's identity, so all certificates of a round carry the same seed. It becomes computable as soon as any `t` participants have signed any vote of the round (including conflicting or nullify votes), so it MUST NOT be used as randomness that a participant could profit from learning before the round resolves. Tempo uses it only for leader election ([simplex.md](simplex.md), [../07-consensus.md](../07-consensus.md) §6), which takes the 48 compressed bytes as input.

## 7. Transcript

The **transcript** is a BLAKE3-based construction that absorbs framed data and produces 32-byte **summaries**, derived transcripts and pseudorandom streams. The DKG uses it to bind messages to a round ([dkg.md](dkg.md)) and the p2p handshake uses it to derive keys ([p2p.md](p2p.md)). BLAKE3 is specified at [github.com/BLAKE3-team/BLAKE3-specs](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf).

### 7.1 State and start tags

A transcript is a running BLAKE3 hasher `hasher`, a counter `pending` (bytes absorbed since the last frame), and a version (`V0` or `V1`). Both the DKG and the handshake use **`V0`**.

| Start tag | Byte | Hasher |
|---|---|---|
| `New` | `0x00` | BLAKE3 in hash mode (unkeyed) |
| `Resume` | `0x01` | BLAKE3 in keyed-hash mode with the given 32-byte summary as key |
| `Fork` | `0x02` | keyed with the parent's summary |
| `Noise` | `0x03` | keyed with the parent's summary |

```python
def start(tag, key=None, version="V0"):
    t = Transcript(hasher=blake3(key=key) if key else blake3(), pending=0, version=version)
    t.hasher.update(bytes([tag]))
    return t
```

### 7.2 Operations

```python
def frame(n, version):                          # length frame for n absorbed bytes
    v = varint(n)
    return v if version == "V0" else reversed(v)

def flush(t):
    t.hasher.update(frame(t.pending, t.version)); t.pending = 0

def new(namespace, version):  t = start(0x00, None, version); commit(t, namespace); return t
def resume(summary, version): return start(0x01, summary, version)          # no commit
def append(t, data):          t.hasher.update(data); t.pending += len(data)
def commit(t, data):          append(t, data); flush(t)

def summarize(t) -> bytes32:
    h = t.hasher.copy()
    if t.pending != 0:
        h.update(frame(t.pending, t.version))   # an unflushed append is framed; nothing otherwise
    return h.digest()                           # 32 bytes

def fork(t, label):  f = start(0x02, summarize(t), t.version); commit(f, label); return f
def noise(t, label): n = start(0x03, summarize(t), t.version); commit(n, label); return n.hasher.xof()
```

Rules that follow from the definitions:

- `commit(t, b"")` absorbs the frame `0x00`. A transcript with nothing pending absorbs nothing at `summarize`.
- `append(a); commit(b)` equals `commit(a ‖ b)`.
- `summarize`, `fork` and `noise` do not modify `t`.
- `noise` returns the BLAKE3 extendable output of the derived hasher, read from offset 0 as one continuous stream. A 64-bit value drawn from it is the next 8 bytes, little-endian.
- `V0` and `V1` differ only when a frame's varint is longer than one byte (`pending ≥ 128`).

### 7.3 Summary encoding

```text
Summary = hash[32]          # the BLAKE3 output; any 32 bytes decode
```

Summaries compare by lexicographic order of their bytes.

### 7.4 Signing a summary

A transcript or summary is signed with an Ed25519 key under the empty namespace:

```text
sign_summary(k, S)            = sign(k, b"", S)              = ed25519_sign(k, 0x00 ‖ S)
verify_summary(A, S, sig)     = verify(A, b"", S, sig)
```

The signed payload is 33 bytes. Batch verification of summary signatures follows §3.6.

### 7.5 Transcript test vectors (V0)

| Operation | Result |
|---|---|
| `summarize(new(b"test"))` = `BLAKE3(00 74657374 04)` | `83c46a9c54cfc5eeaa875cedcdb484d3b4e7958a1c0674789c7703f6adcbb916` |
| `T = new(b"test"); commit(T, b"abc"); summarize(T)` | `78bb7a0c9e01421b6068d9796ee28b7479daf1b69e47a9d778c3219f70d01c2b` |
| `summarize(fork(T, b"label"))` | `60ce9e79618520ef0cf3da9e9ae19b99b741032ff5f3bdcae4855f130fe239c7` |
| first 32 bytes of `noise(T, b"label")` | `2317ffc2730000cac80001049844063a84cd6acf344f1a18e62edeb0d5885be6` |
| `summarize(resume(summarize(T)))` | `061d227c5fd233f3dc04e5c4d25be075e8f392cb906f0d2a64af8e7330c5bdb1` |
| `sign_summary(k, summarize(T))`, `k` = the §3.7 seed | `8d691566d2f5c0f75aa1e58a4ce77b25e98ee0f5ad28c3a61deddc8e725f38876a56b07780e8b8dfda4fc2aa6c290d6268c6f95cd2220f9ac9e3b86931a6ec0c` |

## 8. Conformance summary

A conforming implementation MUST:

1. Accept exactly the Ed25519 public keys of §3.2 and the signatures of §3.4. RFC 8032 strict verifiers do not qualify.
2. Reject, when decoding a G1 or G2 point, the uncompressed form, the point at infinity, `x ≥ p`, points off the curve and points outside the order-`r` subgroup (§4.3).
3. Reject scalars `≥ r`, and a zero share secret (§4.2, §5.2).
4. Hash with RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` and DST `BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_` over `union_unique(ns, msg)` (§4.4), and reject identity signatures (§4.5).
5. Decode sharings with mode version 0 and the bounds of §5.4, with `total` as a 4-byte big-endian integer.
6. Treat batch verification as a shortcut for individual verification (§3.6, §4.6).

