# Commonware codec and shared primitives

This chapter specifies the binary codec that Tempo's consensus layer uses for every consensus, DKG and validator-network message, and the small shared primitives built on it: namespaced message construction, big-endian modulo reduction, the `N3f1` fault model, the epoch, view, height and round counters, and fixed-length epoch arithmetic. The codec is the one of commonware 2026.9.0. This chapter restates it so that an implementation needs no commonware source.

The other chapters of this folder use the notation of §2:

- [cryptography.md](cryptography.md): Ed25519, BLS12-381 MinSig, threshold BLS and the threshold VRF.
- [dkg.md](dkg.md): the Feldman–Desmedt DKG and its messages.
- [simplex.md](simplex.md): Simplex votes, certificates and leader election.
- [p2p.md](p2p.md): the authenticated `lookup` network and the encrypted stream.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

## 1. Scope

The codec is a schema-driven, non-self-describing binary format. A value's bytes carry no type tags, field names or overall length. The reader knows the type it expects and, for variable-length types, a *decode configuration* that bounds lengths (§5.4).

This chapter covers only the parts Tempo uses:

- unsigned LEB128 varints for `u16`, `u32` and `u64` (§3);
- fixed-width big-endian integers (§4);
- `bool`, `Option`, fixed arrays, length-prefixed sequences and byte strings, tuples and structs, tagged unions, and deferred fixed-size fields (§5);
- sorted, deduplicated sets and maps (§6);
- `union`, `union_unique`, `modulo` and mode lists (§7);
- the `N3f1` fault model (§8);
- epoch, view, height, round and participant-index types (§9);
- fixed-length epochs and their phases (§10);
- the read and decode rules for whole messages (§11).

Tempo's consensus formats use no signed (zig-zag) varints, no floating-point values, no hash maps or hash sets, and no bit vectors. In particular, the threshold VRF certificates Tempo uses carry no signer bitmap. An implementation does not need those encodings.

## 2. Notation

This notation is shared by every chapter under `specs/commonware/`.

| Notation | Meaning |
|---|---|
| `a ‖ b` | Concatenation of byte strings `a` and `b` |
| `len(x)` | Number of bytes in byte string `x`, or number of items in a sequence |
| `enc(x)` | The codec encoding of value `x` under its type |
| `varint(x)` | Unsigned LEB128 encoding of integer `x` (§3). The integer type is `u64` unless stated, such as `varint_u32(x)` |
| `u8(x)`, `u16be(x)`, `u32be(x)`, `u64be(x)` | Fixed-width big-endian encoding of `x` in 1, 2, 4 or 8 bytes (§4) |
| `bool(b)` | One byte, `0x00` for false and `0x01` for true (§5.1) |
| `option(T)` | `bool(present)` followed by `enc(value)` when present (§5.2) |
| `T[N]` or `bytes[N]` | Fixed array of `N` items of type `T`, or `N` raw bytes, with no length prefix (§5.3) |
| `vec(T, R)` | `varint_u32(n) ‖ enc(item₀) ‖ … ‖ enc(itemₙ₋₁)`, where the decoder requires `n ∈ R` (§5.4) |
| `bytes(R)` | `vec(u8, R)`, a length-prefixed byte string. `bytes(x)` also denotes the encoding `varint_u32(len(x)) ‖ x` |
| `set(T, R)` | An ordered set: `vec(T, R)` whose items strictly increase (§6.1) |
| `map(K, V, R)` | An ordered map: `set(K, R) ‖ vec(V, exactly n)` (§6.2) |
| `R` ranges | Written as Rust-style ranges of item counts: `a..=b` (inclusive), `a..b` (end excluded), `a..` (no upper bound), `..` (any) |
| `b"…"` | The ASCII bytes of the string, without a terminator |
| `0x…` | Hex bytes, most significant first |
| `x // y`, `x % y` | Integer division and remainder, on non-negative integers |

Structures are written as a field list. A structure encodes as the concatenation of its fields' encodings in the listed order, with no padding, separators or length prefix (§5.5).

All lengths, counts and item bounds are integers. "`n ∈ a..=b`" means `a ≤ n ≤ b`.

## 3. Varint

### 3.1 Encoding

`varint(x)` is unsigned LEB128, the base-128 little-endian encoding also used by [Protocol Buffers](https://protobuf.dev/programming-guides/encoding/#varints). Each byte carries 7 data bits in its low bits. The high bit `0x80` is the *continuation bit*: it is set on every byte except the last. The first byte holds the least significant 7 bits.

```python
def varint(x: int) -> bytes:
    assert x >= 0
    out = bytearray()
    while x >= 0x80:
        out.append((x & 0x7F) | 0x80)
        x >>= 7
    out.append(x)
    return bytes(out)
```

The encoder always emits the shortest form: `max(1, ceil(bits(x) / 7))` bytes, where `bits(x)` is the position of the highest set bit (`bits(0) = 0`).

Each varint has an integer type that fixes its maximum value and length:

| Type | Maximum value | Maximum length | Allowed value of the final byte when the encoding is the maximum length |
|---|---|---|---|
| `u16` | 65,535 | 3 bytes | `0x01..=0x03` |
| `u32` | 4,294,967,295 | 5 bytes | `0x01..=0x0F` |
| `u64` | 18,446,744,073,709,551,615 | 10 bytes | `0x01` |

Epochs, views, heights and every other consensus counter are `u64` varints (§9). Lengths and counts are `u32` varints (§5.4). Participant indices are `u32` varints (§9.2).

### 3.2 Decoding and canonical form

A decoder MUST accept exactly the encodings the encoder produces, and MUST reject every other byte string. It reads one byte at a time:

```python
def read_varint(buf, type_bits: int) -> int:       # type_bits = 16, 32 or 64
    result, shift = 0, 0
    while True:
        b = buf.read_u8()                           # end of input: reject (truncated)
        if b == 0x00 and shift > 0:
            reject("overlong")                      # a zero byte after the first byte
        remaining = type_bits - shift
        if remaining <= 7 and b.bit_length() > remaining:
            reject("overflow")                      # the byte, including its continuation bit,
                                                    # must fit in the remaining value bits
        result |= (b & 0x7F) << shift
        if b & 0x80 == 0:
            return result
        shift += 7
```

These checks make the decoder reject exactly:

- **Truncation.** The input ends before a byte without the continuation bit.
- **Overlong (non-canonical) forms.** Any final byte `0x00` after the first byte, such as `0x80 0x00` for 0 or `0x81 0x00` for 1. A shortest-form encoding never ends in `0x00` unless it is the single byte `0x00`, and every overlong form ends in `0x00`, so this check rejects all of them. A zero continuation byte `0x80` in the middle is allowed: `0x80 0x80 0x01` is the canonical encoding of 16,384.
- **Overflow.** A value above the type's maximum, or an encoding longer than the type's maximum length. When the bits still available are 7 or fewer, the whole byte, continuation bit included, must fit in them. So a `u64` varint's 10th byte MUST be `0x01`, a `u32` varint's 5th byte MUST be in `0x01..=0x0F`, and a `u16` varint's 3rd byte MUST be in `0x01..=0x03`.

The decoded value is unique, and re-encoding it yields the input bytes.

### 3.3 Varint test vectors

| Value | `varint` |
|---|---|
| 0 | `00` |
| 1 | `01` |
| 127 | `7f` |
| 128 | `80 01` |
| 255 | `ff 01` |
| 300 | `ac 02` |
| 2,042 | `fa 0f` |
| 16,383 | `ff 7f` |
| 16,384 | `80 80 01` |
| 21,600 | `e0 a8 01` |
| 2³² − 1 | `ff ff ff ff 0f` |
| 2⁶³ | `80 80 80 80 80 80 80 80 80 01` |
| 2⁶⁴ − 1 | `ff ff ff ff ff ff ff ff ff 01` |

Rejected inputs:

| Input | Type | Reason |
|---|---|---|
| `80` | any | Truncated |
| `80 00`, `81 00`, `ff 00` | any | Overlong (zero final byte) |
| `ff ff ff ff ff ff ff ff ff 02` | `u64` | Overflow (10th byte above `0x01`) |
| `ff ff ff ff ff ff ff ff ff 81 01` | `u64` | Overflow (10th byte has the continuation bit) |
| `ff ff ff ff 10` | `u32` | Overflow (5th byte above `0x0F`) |
| `80 80 80 80 80 01` | `u32` | Overflow (6 bytes) |
| `ff ff 04` | `u16` | Overflow (3rd byte above `0x03`) |
| `01 00` | any, decoded as a whole message | Trailing byte (§11) |

## 4. Fixed-width integers

Fixed-width integers encode as their two's-complement value in network byte order (big-endian), with exactly their width in bytes:

| Type | Bytes | Encoding |
|---|---|---|
| `u8` | 1 | the byte |
| `u16` | 2 | `u16be` |
| `u32` | 4 | `u32be` |
| `u64` | 8 | `u64be` |

A decoder MUST reject the value when fewer than the width's bytes remain. Every bit pattern is a valid value.

A *non-zero* fixed-width integer (such as a non-zero `u32`) uses the same encoding, and its decoder MUST also reject the all-zero value.

Examples: `u16` 0x0102 is `01 02`. `u32` 0x01020304 is `01 02 03 04`. `u64` 1 is `00 00 00 00 00 00 00 01`.

Each chapter states whether an integer field is a varint or fixed-width. The two are never interchangeable.

## 5. Composite types

### 5.1 Bool

`bool` is one byte: `0x00` is false and `0x01` is true. A decoder MUST reject any other byte value and an empty input.

### 5.2 Option

`Option<T>` encodes as `bool(present)`, followed by `enc(value)` only when present:

```
None     = 0x00
Some(v)  = 0x01 ‖ enc(v)
```

A decoder MUST reject a tag byte other than `0x00` or `0x01`. The decode configuration of `Option<T>` is that of `T`.

Example: `Option<u8>` `None` is `00` and `Some(7)` is `01 07`. The input `02 07` is rejected.

### 5.3 Fixed arrays

A fixed array `T[N]`, whose length `N` the type fixes, encodes as the concatenation of its `N` items with no length prefix. A raw byte array `bytes[N]` is `N` bytes copied as-is.

Fixed-size values such as digests (`bytes[32]`), Ed25519 public keys (32 bytes) and compressed BLS12-381 points (48 or 96 bytes) are fixed arrays. Their decoders may apply further checks, such as point validation, which [cryptography.md](cryptography.md) specifies. A decoder MUST reject the value when fewer than the array's bytes remain.

### 5.4 Length-prefixed sequences and bytes

A variable-length sequence of items of type `T` encodes as a `u32` varint item count followed by the items:

```
vec(T, R) = varint_u32(n) ‖ enc(item_0) ‖ … ‖ enc(item_{n−1})
```

For a byte string (`bytes(R)`), the items are single bytes, so the encoding is `varint_u32(len) ‖ raw bytes`.

The count is a count of *items*, not of bytes, except for byte strings, where they coincide. The count is a `u32` varint (at most 5 bytes, §3.2). An encoder MUST NOT encode a sequence of more than 2³² − 1 items.

Every length-prefixed field has a decode range `R` (the *range configuration*), fixed by the format that contains the field. A decoder MUST:

1. read the count `n` as a `u32` varint and reject it under the rules of §3.2;
2. reject the value when `n ∉ R`, before reading any item;
3. read exactly `n` items, rejecting the value when any item is invalid or the input ends.

A decoder SHOULD NOT reserve memory for `n` items before reading them, beyond what the remaining input can hold, because `n` comes from untrusted input.

Examples:

| Value | Type | Encoding |
|---|---|---|
| `b"abc"` | `bytes(..)` | `03 61 62 63` |
| `[1, 2]` | `vec(u16, ..)` | `02 00 01 00 02` |

Rejected: `03 61 62 63` as `bytes(0..=2)` (count 3 outside the range); `05 61` as `bytes(..)` (input ends after 1 of 5 bytes).

### 5.5 Tuples and structs

A tuple `(A, B, …)` or a structure encodes as the concatenation of its members' encodings in declaration order. Nothing marks the boundary between members: each member's own encoding determines where it ends. A member's decode configuration comes from the containing format.

Example: the tuple `(u8 5, bool true, varint 300)` is `05 01 ac 02`.

### 5.6 Tagged unions (enums)

A value of a type with several variants encodes as a one-byte tag followed by the variant's fields as a structure (§5.5):

```
enum_value = u8(tag) ‖ enc(fields of the variant)
```

Each format lists its tags, numbered from 0 in declaration order unless it says otherwise. A decoder MUST reject an unknown tag. A variant with no fields is the tag byte alone.

For example, a DKG network message (see [dkg.md](dkg.md)) is `0x00 ‖ DealerPubMsg ‖ DealerPrivMsg` or `0x01 ‖ PlayerAck`, and any other first byte is rejected.

### 5.7 Deferred fixed-size fields

Some formats read a fixed-size field without validating it during decoding. Such a field is a *deferred* field, and the containing format says which fields are deferred:

- Decoding a deferred field of size `S` takes exactly the next `S` bytes as raw bytes, and fails only when fewer than `S` bytes remain.
- The field's own validity checks, such as BLS12-381 point validation, run when the value is first used. A value that fails them makes that use fail (for example, a signature check returns false). It doesn't make the containing message undecodable.
- Re-encoding a deferred field writes back its original `S` bytes.

The threshold VRF votes and certificates carry their signatures as deferred fields (see [cryptography.md](cryptography.md) and [simplex.md](simplex.md)).

## 6. Ordered collections

### 6.1 Ordered set

An ordered set of items of type `T` encodes exactly as `vec(T, R)` (§5.4), with the items in strictly increasing order under `T`'s ordering:

```
set(T, R) = varint_u32(n) ‖ enc(item_0) ‖ … ‖ enc(item_{n−1})      with item_0 < item_1 < … < item_{n−1}
```

A decoder MUST read it as `vec(T, R)` (checking `n ∈ R` and each item) and then MUST reject it if any adjacent pair has `item_{i−1} ≥ item_i`. So an unsorted set and a set with a duplicate item are both rejected. An encoder MUST sort the items and MUST NOT emit duplicates.

The position of an item in the set is its *index*, starting at 0. Participant indices (§9.2) are positions in an ordered set of public keys.

Item orderings used by Tempo:

| Item type | Order |
|---|---|
| Unsigned integers | Numeric order |
| Byte arrays, digests | Lexicographic order of the bytes |
| Ed25519 public keys | Lexicographic order of the 32-byte encoding (see [cryptography.md](cryptography.md#31-ed25519-encodings)) |

Example: the set `{3, 1, 2}` of `u16` is `03 00 01 00 02 00 03`. The inputs `02 00 02 00 01` (unsorted) and `02 00 01 00 01` (duplicate) are rejected.

### 6.2 Ordered map

An ordered map from keys of type `K` to values of type `V` encodes *all keys first, then all values*, each as its own length-prefixed sequence:

```
map(K, V, R) = set(K, R) ‖ vec(V, n..=n)
             = varint_u32(n) ‖ enc(k_0) ‖ … ‖ enc(k_{n−1}) ‖ varint_u32(n) ‖ enc(v_0) ‖ … ‖ enc(v_{n−1})
```

The keys strictly increase, and `v_i` is the value of `k_i`. The count appears twice. A decoder MUST:

1. decode the keys as `set(K, R)` (§6.1), giving `n` keys;
2. decode the values as `vec(V, R')` with `R' = n..=n`, so a second count other than `n` is rejected.

This layout differs from an interleaved key–value encoding. Implementations MUST NOT interleave keys and values.

Example: the map `{2: true, 1: false}` from `u8` to `bool` is `02 01 02 02 00 01`. The input `02 01 02 01 00` is rejected because the value count 1 differs from the key count 2.

### 6.3 Ordered bidirectional map

An ordered bidirectional map is an ordered map whose values are also pairwise distinct. It encodes exactly as an ordered map (§6.2). Its decoder also rejects the value when two keys have equal values. No Tempo wire format in this folder contains a bidirectional map. The type appears only inside implementations.

## 7. Byte utilities

### 7.1 union

`union(a, b)` is the plain concatenation `a ‖ b`. It derives one namespace from another, such as `union(b"TEMPO", b"_SEED") = b"TEMPO_SEED"` (`54 45 4d 50 4f 5f 53 45 45 44`).

`union` is not injective: different pairs can give the same bytes. Signing domains therefore use `union_unique`.

### 7.2 union_unique

`union_unique(namespace, msg)` prefixes the namespace with its length:

```
union_unique(ns, msg) = varint_u32(len(ns)) ‖ ns ‖ msg
```

The length is a `u32` varint (§3), so a namespace of 128 bytes or more has a multi-byte prefix. Because the prefix fixes where the namespace ends, every `(ns, msg)` pair maps to a distinct byte string. Every signed message in Tempo's consensus layer is `union_unique(ns, msg)` for its namespace (see [cryptography.md](cryptography.md#2-namespaced-messages)).

Test vectors:

| `ns` | `msg` | `union_unique(ns, msg)` |
|---|---|---|
| `b"TEMPO"` | `b"_P2P"` | `05 54 45 4d 50 4f 5f 50 32 50` |
| `b"TEMPO_NOTARIZE"` | `01 02` | `0e 54 45 4d 50 4f 5f 4e 4f 54 41 52 49 5a 45 01 02` |
| 200 bytes `0x61` | empty | `c8 01 61 61 …` (prefix `c8 01`, then the 200 bytes) |

### 7.3 modulo

`modulo(bytes, n)` reduces a byte string, read as a big-endian unsigned integer of any length, modulo a non-zero `u64` `n`:

```python
def modulo(data: bytes, n: int) -> int:
    assert 0 < n < 2**64                            # n == 0 is a programming error
    r = 0
    for b in data:
        r = ((r << 8) | b) % n
    return r                                        # == int.from_bytes(data, "big") % n
```

The empty string gives 0. The result equals `int.from_bytes(data, "big") % n`, so implementations MAY compute it with arbitrary-precision arithmetic. Leader election uses it to reduce a seed signature or its hash to a participant index (see [simplex.md](simplex.md)).

Test vectors: `modulo(0x, 7) = 0`; `modulo(0x0100, 7) = 4`; for 48 bytes of `0xff`, `modulo(·, 4) = 3`, `modulo(·, 5) = 0` and `modulo(·, 100) = 15`.

### 7.4 Modes

A *mode list* records a short, fixed-capacity list of small version numbers, each in `0..=127`. The DKG commits it into a round's transcript (see [dkg.md §3.3](dkg.md#33-round-summary)). A list `[m_0, …, m_{N−1}]` of capacity `N` encodes as follows:

```python
def encode_modes(modes: list[int]) -> bytes | None:
    assert all(0 <= m < 128 for m in modes)
    last = max((i for i, m in enumerate(modes) if m != 0), default=None)
    if last is None:
        return None                                 # all modes zero: no encoding; the field is omitted
    return bytes([m | 0x80 for m in modes[:last]] + [modes[last]])
```

Trailing zero modes are dropped. Every byte except the last has the continuation bit `0x80`, and the last byte is non-zero. When every mode is zero, the list has no encoding, and the format that contains it omits it entirely.

A decoder of capacity `N` reads bytes until one has the continuation bit clear. It MUST reject the list if that byte is `0x00`, if `N` bytes all have the continuation bit set, or if the input ends. Omitted trailing modes are 0.

Example with `N = 2`: `[0, 0]` is omitted, `[1, 0]` is `01`, `[0, 1]` is `80 01` and `[1, 1]` is `81 01`.

## 8. Fault model N3f1

Tempo uses the Byzantine fault model `N3f1`, under which `n` participants tolerate `f` faults with `n ≥ 3f + 1`:

```python
def max_faults(n: int) -> int:     # f
    assert n > 0
    return (n - 1) // 3

def quorum(n: int) -> int:         # q
    assert n > 0
    return n - max_faults(n)
```

`n` MUST be in `1..=2³² − 1`. Both functions are undefined for `n = 0`, and an implementation MUST NOT call them with it.

| `n` | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 10 | 16 | 19 | 100 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `f` | 0 | 0 | 0 | 1 | 1 | 1 | 2 | 3 | 5 | 6 | 33 |
| `q` | 1 | 2 | 3 | 3 | 4 | 5 | 5 | 7 | 11 | 13 | 67 |

The quorum of an ordered set of participants is `quorum(len(set))`. Simplex certificates and the DKG threshold both use `q` (see [simplex.md](simplex.md) and [dkg.md](dkg.md)).

## 9. Consensus counters

### 9.1 Epoch, view, height and round

| Type | Value | Encoding |
|---|---|---|
| `Epoch` | `u64` | `varint(epoch)` |
| `View` | `u64` | `varint(view)` |
| `Height` | `u64` | `varint(height)` |
| `Round` | `(epoch: Epoch, view: View)` | `varint(epoch) ‖ varint(view)` |

- An **epoch** is a period with one validator set and one Simplex instance.
- A **view** counts Simplex rounds within an epoch.
- A **height** is a block number.
- A **round** is an `(epoch, view)` pair. Rounds are ordered by epoch first, then by view.

Decoders apply the `u64` varint rules of §3.2. Any `u64` value decodes. Bounds such as "view ≥ 1" belong to the formats that use these types.

Example: `Round(epoch 0, view 1)` is `00 01`, and `Round(2042, 300)` is `fa 0f ac 02`.

Incrementing a counter past 2⁶⁴ − 1 is an error. An implementation MUST NOT wrap around.

### 9.2 Participant index

A **participant index** is the 0-based position of a participant's public key in the ordered set of participants (§6.1). It encodes as `varint_u32(index)` and decodes under the `u32` rules of §3.2. A format that receives an index MUST check that it is less than the number of participants. The decoder itself doesn't check this.

## 10. Fixed-length epochs

Tempo divides heights into epochs of a fixed length `L` (see [07-consensus.md](../07-consensus.md) for the value of `L` on each network). `L` MUST be at least 2.

### 10.1 Epoch bounds

```python
def epoch_of(h: int) -> int:     return h // L
def first(e: int) -> int | None: return checked(e * L)                # None if it exceeds 2**64 - 1
def last(e: int) -> int | None:  return checked(e * L + L - 1)
def midpoint(e: int) -> int | None: return checked(e * L + L // 2)

def containing(h: int):                                               # epoch info of height h
    e = epoch_of(h)
    if last(e) is None:
        return None                                                   # the final, partial epoch
    return EpochInfo(epoch=e, height=h, first=first(e), last=last(e))
```

`checked(x)` returns `x` when it fits in a `u64` and `None` otherwise. An epoch whose last height would exceed 2⁶⁴ − 1 has no bounds, so heights in it belong to no epoch. Real chains never reach such heights.

Epoch 0 covers heights `0..=L−1` and includes height 0.

Mainnet example with `L = 21600`: `first(2042) = 44,107,200`, `midpoint(2042) = 44,118,000` and `last(2042) = 44,128,799`.

### 10.2 Phases

For a height `h` with epoch info `info`, the *relative height* is `h − info.first` and the epoch length is `info.last − info.first + 1 = L`. The phase is:

```python
def phase(info) -> str:
    relative = info.height - info.first
    mid = (info.last - info.first + 1) // 2           # L // 2
    if relative < mid:  return "Early"
    if relative == mid: return "Midpoint"
    return "Late"
```

So exactly one height per epoch, `midpoint(e)`, is `Midpoint`. For `L = 21600`, relative heights `0..=10799` are `Early`, `10800` is `Midpoint` and `10801..=21599` are `Late`. The DKG uses phases for timing (see [dkg.md](dkg.md)).

## 11. Decoding rules

A conforming decoder MUST reject any input the rules of this chapter and of the containing format don't allow. The error a decoder reports is not normative: only acceptance or rejection is.

Formats parse their input in one of two ways:

- **Decode.** Parse a value from a complete byte string. The value MUST use every byte: a decoder MUST reject the input if any bytes remain after the value, such as `01 00` decoded as a varint. Unless a format says otherwise, every message, field payload and stored record is decoded this way, so each accepted value has exactly one encoding.
- **Read.** Parse a value from the start of a byte string and leave the remaining bytes for the caller. Values nested inside other values are read: the containing value's decoder reads each field in turn, and only the outermost value is decoded. A format that reads a top-level value without decoding it, such as the execution layer's check of a boundary block's `extra_data` (see [05-block-execution.md](../05-block-execution.md)), says so explicitly.

Each value's encoding is a deterministic function of the value. Implementations MUST encode exactly as specified, with shortest-form varints, sorted and deduplicated sets and map keys, and `0x00` or `0x01` booleans. A byte string that a peer signed or hashed is checked against the canonical encoding of the decoded value, and the decoder's canonical-form checks guarantee that the two are the same bytes.
