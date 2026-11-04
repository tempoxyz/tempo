# 03 — Signatures and sender recovery

This chapter defines every signature scheme a Tempo transaction or authorization can carry on mainnet up to and including T13: how each is encoded, decoded and verified, which digest it signs, how the sender and the fee payer are recovered, how signatures inside EIP-7702 authorizations are handled, and how much intrinsic gas each scheme costs.

Field-level RLP of the transactions and of `KeyAuthorization` is in [02-encoding.md](02-encoding.md). The validation pipeline that uses the recovered addresses (nonces, fees, key authorizations, access-key checks) is in [06-transactions-and-fees.md](06-transactions-and-fees.md), and the access-key state the keychain checks is in [precompiles/account-keychain.md](precompiles/account-keychain.md). Fork predicates ("From Tn", "Before Tn") are as defined in [01-chain-and-forks.md](01-chain-and-forks.md). Mainnet runs T0 from genesis, so no pre-T0 rule applies to it.

## 1. Notation and constants

```python
SECP256K1_N      = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_N_HALF = SECP256K1_N // 2   # 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0

P256_N           = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
P256_N_HALF      = P256_N // 2        # 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8

P256_P           = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF  # field prime

SECP256K1_SIGNATURE_LENGTH    = 65
P256_SIGNATURE_LENGTH         = 129   # payload after the 0x01 type byte
MAX_WEBAUTHN_SIGNATURE_LENGTH = 2048  # payload after the 0x02 type byte
MIN_AUTH_DATA_LEN             = 37

SIGNATURE_TYPE_P256                 = 0x01
SIGNATURE_TYPE_WEBAUTHN             = 0x02
SIGNATURE_TYPE_KEYCHAIN             = 0x03   # Keychain V1
SIGNATURE_TYPE_KEYCHAIN_V2          = 0x04   # Keychain V2
SIGNATURE_TYPE_CONFIGURABLE_ACCOUNT = 0x05   # invalid at or before T13 (section 9)

TEMPO_TX_TYPE_ID               = 0x76
FEE_PAYER_SIGNATURE_MAGIC_BYTE = 0x78
EIP7702_MAGIC                  = 0x05

SECP256K1_VERIFY_GAS   = 3_000
P256_VERIFY_GAS        = 8_000
WEBAUTHN_VERIFY_GAS    = 8_000
KEYCHAIN_VALIDATION_GAS = 3_000   # COLD_SLOAD_COST (2_100) + 900
```

- `keccak256`, `sha256`: the usual 32-byte hashes. `||`: byte concatenation. `be32(x)`: 32-byte big-endian encoding. `int(b)`: big-endian unsigned integer of bytes `b`.
- `base64url_nopad(b)`: RFC 4648 §5 Base64 with the URL-safe alphabet (`A-Z a-z 0-9 - _`) and **no** `=` padding. For a 32-byte input it is always 43 ASCII characters.
- `address_from_pubkey(x, y) = keccak256(be32(x) || be32(y))[12:32]`: the 20-byte address of an affine public key, used by every scheme in this chapter (for secp256k1 it is the usual Ethereum address).
- "Invalid transaction": a transaction that MUST NOT appear in a valid block. A block containing an undecodable transaction, a transaction whose sender cannot be recovered, or an invalid transaction is invalid (see [05-block-execution.md](05-block-execution.md)). The layer at which a rule fires (decode, recovery or validation) is stated for implementers' error reporting; for block validity all three are equivalent.

## 2. Where signatures appear

| Location | Field type | Schemes allowed | Section |
|---|---|---|---|
| Legacy (0x00), EIP-2930 (0x01), EIP-1559 (0x02), EIP-7702 (0x04) transaction signature | `(y_parity / v, r, s)` | secp256k1 | 4, 11 |
| EIP-7702 (0x04) authorization list entries | `(y_parity, r, s)` | secp256k1 | 12.1 |
| 0x76 `sender_signature` (last field) | `TempoSignature` | secp256k1, P256, WebAuthn, Keychain V1/V2 | 3–8, 11 |
| 0x76 `fee_payer_signature` | `(y_parity, r, s)` list | secp256k1 | 11.3 |
| 0x76 `tempo_authorization_list[i].signature` | `TempoSignature` | secp256k1, P256, WebAuthn (Keychain decodes but is skipped) | 12.2 |
| 0x76 `key_authorization.signature` | `AccountSignature` | secp256k1, P256, WebAuthn | 13 |
| Pre-T4 subblock-metadata system transaction | Legacy, `r = s = 0`, parity 0 | none (sentinel) | 11.4 |

EIP-4844 (0x03) transactions are not part of the Tempo envelope (see [02-encoding.md](02-encoding.md)); "type 0x03" in this chapter always means the Keychain V1 *signature* type byte.

The precompiles that verify signatures for contracts (the SignatureVerifier from T3, the keychain's verification helpers) reuse the primitive schemes of sections 4–6 exactly; their ABI and their own restrictions are in [precompiles/account-keychain.md](precompiles/account-keychain.md). The EVM's P256VERIFY precompile (0x100, from T1C) is the EIP-7951 precompile and is unrelated to transaction signatures (see [precompiles/00-framework.md](precompiles/00-framework.md)).

## 3. Signature byte formats and decoding

A `TempoSignature` and an `AccountSignature` are carried as one RLP **byte string** (never a list); an RLP list where a signature is expected is a decode error. The string's payload is decoded as below. Any decode failure makes the enclosing transaction undecodable.

### 3.1 Layouts

| Scheme | Total length (bytes) | Layout |
|---|---|---|
| secp256k1 | exactly 65 | `r(32) \|\| s(32) \|\| v(1)` — no type byte |
| P256 | exactly 130 | `0x01 \|\| r(32) \|\| s(32) \|\| pub_key_x(32) \|\| pub_key_y(32) \|\| pre_hash(1)` |
| WebAuthn | 129 to 2049 | `0x02 \|\| webauthn_data(0..1920) \|\| r(32) \|\| s(32) \|\| pub_key_x(32) \|\| pub_key_y(32)` |
| Keychain V1 | 21 + inner | `0x03 \|\| user_address(20) \|\| inner`, inner = a primitive signature (secp256k1, P256 or WebAuthn) |
| Keychain V2 | 21 + inner | `0x04 \|\| user_address(20) \|\| inner`, inner = a primitive signature (or, at decode level only, a 0x05 signature) |
| Configurable account | ≥ 2 | `0x05 \|\| rlp(ConfigurableAccountSignature)` — invalid at or before T13, see section 9 |

The type is decided by length first: a payload of **exactly 65 bytes is always secp256k1**, whatever its first byte. Every other payload of length ≥ 2 is typed by its first byte. Because a valid P256, WebAuthn or keychain payload is never 65 bytes long, the rule is unambiguous.

### 3.2 Decoding pseudocode

```python
def type_identifier(data: bytes) -> Optional[int]:
    if len(data) >= 2 and len(data) != 65:
        return data[0]
    return None

def decode_primitive(data: bytes) -> PrimitiveSignature:
    if len(data) == 0:
        raise DecodeError("Signature data is empty")
    if len(data) == 65:
        return decode_secp256k1(data)                       # section 4.1
    if len(data) < 2:
        raise DecodeError("too short")
    type_id, payload = data[0], data[1:]
    if type_id == 0x01:
        if len(payload) != 129:
            raise DecodeError("Invalid P256 signature length")
        return P256(r=payload[0:32], s=payload[32:64],
                    x=payload[64:96], y=payload[96:128],
                    pre_hash=(payload[128] != 0))          # any non-zero byte is true
    if type_id == 0x02:
        if not (128 <= len(payload) <= 2048):
            raise DecodeError("Invalid WebAuthn signature length")
        n = len(payload) - 128
        return WebAuthn(webauthn_data=payload[0:n],
                        r=payload[n:n+32], s=payload[n+32:n+64],
                        x=payload[n+64:n+96], y=payload[n+96:n+128])
    raise DecodeError("Unknown signature type identifier")

def decode_account_signature(data: bytes) -> AccountSignature:
    t = type_identifier(data)
    if t in (0x03, 0x04):
        raise DecodeError("keychain signatures are not account signatures")
    if t == 0x05:
        return ConfigurableAccount(rlp_decode_exact(data[1:]))   # see section 9
    return decode_primitive(data)

def decode_tempo_signature(data: bytes) -> TempoSignature:
    if len(data) == 0:
        raise DecodeError("Signature data is empty")
    t = type_identifier(data)
    if t in (0x03, 0x04):
        version = V1 if t == 0x03 else V2
        body = data[1:]
        if len(body) < 20:
            raise DecodeError("too short for user_address")
        inner = decode_account_signature(body[20:])   # nested keychain -> DecodeError
        if version == V1 and inner.is_configurable_account():
            raise DecodeError("configurable account access keys require keychain V2")
        return Keychain(user_address=body[0:20], inner=inner, version=version)
    return decode_account_signature(data)
```

Consequences a client MUST reproduce:

- A keychain signature never nests: an inner payload whose type byte is 0x03 or 0x04 (and whose length is not 65) is a decode error.
- The decoder does not check fork activation. Keychain V1 vs V2 is enforced at validation (section 8.4) and 0x05 at validation or recovery (section 9).
- The decoder does not check curve membership, scalar ranges or WebAuthn contents; those are verification failures (sections 4–6).
- `KeyAuthorization.signature` is decoded with `decode_account_signature`, so a keychain-wrapped key-authorization signature is a decode error.

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`PrimitiveSignature::from_bytes`, `AccountSignature::from_bytes`, `TempoSignature::from_bytes`), crates/primitives/src/transaction/tempo_transaction.rs (length constants).

## 4. secp256k1

### 4.1 Decoding and accepted `v`

Inside a `TempoSignature` or `AccountSignature` the 65 bytes are `r || s || v`, with `r` and `s` read as 256-bit big-endian integers (no range check at decode). The last byte `v` maps to a y-parity as follows; any other value is a decode error:

| `v` | y_parity |
|---|---|
| 0 | 0 |
| 1 | 1 |
| 27 | 0 |
| 28 | 1 |
| 35..255 | `(v - 35) % 2` |
| 2..26, 29..34 | decode error |

The chain id is **not** derived from or checked against `v` in the 35..255 range; only the parity is kept.

The Ethereum transaction types (0x00, 0x01, 0x02, 0x04) and `fee_payer_signature` carry `(v or y_parity, r, s)` as RLP integers, per EIP-155 / EIP-2718 for the Ethereum types and as described in section 11.3 for the fee payer.

### 4.2 Verification and recovery

```python
def secp256k1_recover(r: int, s: int, y_parity: int, digest: bytes32) -> Address:
    if s > SECP256K1_N_HALF:            # EIP-2 low-s, all forks
        raise Invalid
    if not (1 <= r < SECP256K1_N) or not (1 <= s < SECP256K1_N):
        raise Invalid
    # Standard ECDSA public-key recovery with recovery id = y_parity (R.x = r, never r + n).
    Q = ecdsa_recover(curve=secp256k1, e=int(digest), r=r, s=s, recid=y_parity)
    if Q is None or Q == INFINITY:
        raise Invalid
    return address_from_pubkey(Q.x, Q.y)
```

`s == SECP256K1_N_HALF` is accepted. This same function, with the EIP-2 check, is used for every secp256k1 signature in this chapter: Ethereum transaction signatures, the 0x76 sender signature, keychain inner signatures, fee payer signatures, EIP-7702 and Tempo authorizations, and key-authorization signatures.

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`PrimitiveSignature::recover_signer`); alloy-consensus 2.5.0 `crypto::secp256k1::recover_signer`; alloy-primitives 1.7.3 `Signature::from_raw_array`, `normalize_v`.

## 5. P256 (secp256r1)

### 5.1 Verification

```python
def p256_verify(r: bytes32, s: bytes32, x: bytes32, y: bytes32, message_hash: bytes32) -> None:
    if int(s) > P256_N_HALF:            # high-s is rejected, never normalized
        raise Invalid
    Q = (int(x), int(y))
    if not on_curve_p256(Q) or int(x) >= P256_P or int(y) >= P256_P:
        raise Invalid                   # invalid public key
    ri, si = int(r), int(s)
    if not (1 <= ri < P256_N) or not (1 <= si < P256_N):
        raise Invalid
    e  = int(message_hash)              # the 32-byte digest is used as-is, not hashed again
    w  = inverse(si, P256_N)
    R  = (e * w % P256_N) * G + (ri * w % P256_N) * Q
    if R == INFINITY or R.x % P256_N != ri:
        raise Invalid
```

This is FIPS 186-4 ECDSA verification over P-256 applied to an already-computed 32-byte digest (no further SHA-256), plus the low-s rule. `s == P256_N_HALF` is accepted; `s > P256_N_HALF` is invalid even though it is a mathematically valid ECDSA signature. Signers MUST normalize: if `s > P256_N_HALF`, use `P256_N - s`.

### 5.2 P256 signatures (type 0x01)

```python
def recover_p256(sig: P256, digest: bytes32) -> Address:
    message_hash = sha256(digest) if sig.pre_hash else digest
    p256_verify(sig.r, sig.s, sig.x, sig.y, message_hash)
    return address_from_pubkey(sig.x, sig.y)
```

`pre_hash` exists for signers (such as Web Crypto) that always hash their input with SHA-256: with `pre_hash` set, the signer signs the 32-byte digest as a message and the verifier hashes it once. There is no public-key recovery: the key is carried in the signature and the address is derived from it.

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`verify_p256_signature_internal`, `derive_p256_address`, `P256N_HALF`).

## 6. WebAuthn (type 0x02)

### 6.1 Layout

`webauthn_data = authenticatorData || clientDataJSON`. Tempo accepts only a 37-byte `authenticatorData`:

| Offset | Size | Field | Checked |
|---|---|---|---|
| 0 | 32 | rpIdHash | no |
| 32 | 1 | flags | yes, see 6.2 |
| 33 | 4 | signCount | no |
| 37 | rest | clientDataJSON | yes, see 6.3 |

### 6.2 Recovery

```python
UP, UV, AT, ED = 0x01, 0x04, 0x40, 0x80

def recover_webauthn(sig: WebAuthn, digest: bytes32) -> Address:
    data = sig.webauthn_data
    if len(data) < MIN_AUTH_DATA_LEN + 32:          # at least 69 bytes
        raise Invalid
    flags = data[32]
    if flags & UP == 0 and flags & UV == 0:
        raise Invalid
    if flags & AT != 0:
        raise Invalid
    if flags & ED != 0:
        raise Invalid
    authenticator_data = data[0:37]
    client_data_json   = data[37:]                   # at least 32 bytes
    if not client_data_json_accepts(client_data_json, base64url_nopad(digest)):   # 6.3
        raise Invalid
    message_hash = sha256(authenticator_data || sha256(client_data_json))
    p256_verify(sig.r, sig.s, sig.x, sig.y, message_hash)
    return address_from_pubkey(sig.x, sig.y)
```

The other flag bits (0x02, 0x08 BE, 0x10 BS, 0x20) are ignored. Origin, `crossOrigin`, rpIdHash and signCount are not checked. There is no `pre_hash` flag for WebAuthn.

`digest` is the digest this signature signs in its context (section 10): for a sender signature it is the transaction's sender signing hash, inside a Keychain V2 envelope the V2 hash, inside an authorization the authorization digest. It is never the transaction hash `keccak256(0x76 || rlp(signed))`.

> **Resolved conflict C-SIG-02**: docs and TIP-0001 say the WebAuthn challenge is the Base64URL "tx_hash"; the code compares it with the signing digest. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](conflicts.md#c-sig-02).

> **Resolved conflict C-SIG-03**: TIP-0001 requires the UP flag and allows AT with CBOR parsing; the code accepts UP or UV and rejects AT and ED. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](conflicts.md#c-sig-03).

### 6.3 clientDataJSON acceptance

`client_data_json_accepts(cdj, expected_challenge)` is true exactly when `cdj` deserializes, with serde_json 1.0.151 `from_slice`, into the borrowed struct `{ "type": &str, "challenge": &str }` (no `deny_unknown_fields`), and then `type == "webauthn.get"` and `challenge == expected_challenge`, compared byte for byte. A client that does not use that library MUST implement the following acceptance rules, which are equivalent:

1. **Framing.** `cdj = ws value ws`, where `ws` is any run of `0x20`, `0x09`, `0x0A`, `0x0D`. No other bytes may precede or follow `value` (no BOM, no second value, no comments).
2. **Top-level value.** `value` MUST be either
   - a JSON **object** (RFC 8259) whose members may appear in any order, or
   - a JSON **array of exactly two elements** `[type, challenge]`, in that order. Arrays with fewer or more elements are rejected.

   Any other top-level value (string, number, literal) is rejected.
3. **Required members (object form).** After unescaping member names, exactly one member named `type` and exactly one named `challenge` MUST be present. A missing member is rejected; a second `type` or `challenge` member is rejected (duplicate field). Member names are decoded as JSON strings, so an escaped name such as `"t\u0079pe"` counts as `type`. Member names MUST be valid UTF-8 with well-formed escapes (a lone UTF-16 surrogate escape is rejected).
4. **Values of `type` and `challenge`** (both forms) MUST be JSON strings whose raw content between the quotes contains **no backslash escape at all**, no raw control character (`0x00`–`0x1F`), and is valid UTF-8. A string that is equal only after unescaping (for example `"webauthn\u002eget"`) is rejected. The raw content MUST equal `webauthn.get` and `expected_challenge` respectively. A non-string value (number, null, object, array, boolean) is rejected.
5. **Other members (object form)** are ignored, any number of times and with duplicate names allowed, provided each is a syntactically valid JSON value: strings must have no raw control characters and syntactically valid escapes (`\"`, `\\`, `\/`, `\b`, `\f`, `\n`, `\r`, `\t`, or `\u` + 4 hex digits; surrogate pairing is **not** checked here, and bytes ≥ 0x80 inside these strings are **not** checked for UTF-8 validity); numbers follow the RFC 8259 grammar (no leading zeros, no `+`, digits required after `.` and in exponents); literals are exactly `true`, `false`, `null`. No nesting-depth limit applies to ignored values (the whole signature is bounded at 2049 bytes). Trailing commas are rejected anywhere.

Example of an accepted `clientDataJSON`, for the digest `0xdeadbeef` followed by 28 zero bytes:

```json
{"type":"webauthn.get","challenge":"3q2-7wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","origin":"https://app.example","crossOrigin":false}
```

The message hash covers `clientDataJSON` exactly as carried, including any whitespace and ignored members.

> **Resolved conflict C-SIG-04**: TIP-0001 checks clientDataJSON by substring search; the code parses it as JSON with the rules above. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](conflicts.md#c-sig-04).

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`verify_webauthn_data_internal`, `ClientDataJson`).

## 7. Canonical re-encoding

Decoding is lenient in two places, and the leniency does not survive into any hash. This is the same rule as [02-encoding.md](02-encoding.md#canonical-re-encoding), stated here for signatures:

- secp256k1 inside a `TempoSignature` / `AccountSignature`: `v` ∈ {0, 1, 27, 28, 35..255} decodes (section 4.1); the canonical encoding writes `v = 27 + y_parity`.
- P256: any non-zero `pre_hash` byte decodes as true; the canonical encoding writes `0x01` for true and `0x00` for false.

All other signature fields re-encode to the bytes they were decoded from (WebAuthn data is carried verbatim; Ethereum-type and fee-payer signatures are RLP integers, whose canonical form RLP decoding already enforces, see [02-encoding.md](02-encoding.md)).

Every hash over a transaction or a structure containing a signature MUST be computed over the **canonical re-encoding** of the decoded value, never over the received bytes. In particular:

- the transaction hash `keccak256(0x76 || rlp(signed_tx))`, and the transactions root of the block header (which uses the same EIP-2718 bytes);
- the 0x76 sender signing hash and fee-payer signing hash (section 10), which embed the canonical encodings of every `tempo_authorization_list` signature and of the `key_authorization` signature;
- the expiring-nonce replay hash ([06-transactions-and-fees.md](06-transactions-and-fees.md)), which is built from the sender signing payload.

So a 0x76 transaction received with an embedded `v = 0` and one received with `v = 27` (all else equal) are the same transaction with the same hash. A block producer SHOULD emit canonical encodings.

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`encode_bytes_into`), crates/primitives/src/transaction/tt_signed.rs (`compute_hash`, `eip2718_encode`).

## 8. Keychain signatures (0x03 V1, 0x04 V2)

A keychain signature lets an **access key** sign for a **root account** (`user_address`). The inner signature is made by the access key; its recovered address is the access key's id (`key_id`).

### 8.1 Effective digest

For a context digest `d` (section 10) and a keychain signature with root `user`:

```python
def keychain_effective_digest(version, d: bytes32, user: Address) -> bytes32:
    if version == V1:
        return d
    # V2: 53-byte preimage
    return keccak256(bytes([0x04]) || d || user)
```

V2 binds the access key's signature to the root account: under V1 the same inner signature is valid for every root that authorized the same key.

### 8.2 Recovery

```python
def recover_keychain(sig: Keychain, d: bytes32) -> Address:
    if sig.version == V1 and sig.inner.is_configurable_account():
        raise Invalid                    # unreachable after decoding, kept for completeness
    digest = keychain_effective_digest(sig.version, d, sig.user_address)
    sig.key_id = recover_account_signature(sig.inner, digest)   # secp256k1 / P256 / WebAuthn
    return sig.user_address
```

The recovered "signer" of a keychain signature is `user_address`, not the access key. Recovery only proves that *some* key signed; whether that key is authorized for `user_address` is a stateful check made during validation:

- the key `key_id` MUST be authorized for `user_address` in the AccountKeychain precompile, not revoked and not expired at the block timestamp (or be authorized by the same transaction's `key_authorization`), as specified in [06-transactions-and-fees.md](06-transactions-and-fees.md) and [precompiles/account-keychain.md](precompiles/account-keychain.md);
- **From T1**, the inner signature's type (secp256k1 = 0, P256 = 1, WebAuthn = 2) MUST equal the signature type stored for that key. Before T1 the type is not compared for an already-authorized key. (A P256 key and a WebAuthn key with the same public key therefore have the same `key_id` but are not interchangeable from T1.)

A keychain signature with an inner WebAuthn signature uses `base64url_nopad(effective digest)` as its challenge.

### 8.3 Use as a transaction signature

When the 0x76 `sender_signature` is a keychain signature, the transaction's sender is `user_address` (section 11.2). Access-key-specific transaction rules (no CREATE as first call from T3, spending limits, call scopes, which keys may carry a key authorization) are in [06-transactions-and-fees.md](06-transactions-and-fees.md).

### 8.4 Fork gating

The version check applies to the transaction's `sender_signature` **and** to every `tempo_authorization_list[i].signature`. It is a validation-layer check: such transactions decode but are invalid.

| | Before T1C | From T1C |
|---|---|---|
| Keychain V1 (0x03) | valid | **invalid** (`LegacyPostT1C`) |
| Keychain V2 (0x04) | **invalid** (`V2BeforeActivation`) | valid |

```python
def validate_keychain_version(sig: TempoSignature, block_timestamp):
    t1c = fork_active(T1C, block_timestamp)
    if t1c and sig.is_keychain() and sig.version == V1:
        raise InvalidTransaction("LegacyPostT1C")
    if not t1c and sig.is_keychain() and sig.version == V2:
        raise InvalidTransaction("V2BeforeActivation")
```

Reference implementation: crates/primitives/src/transaction/tt_signature.rs (`KeychainSignature::signing_hash`, `key_id`, `TempoSignature::validate_version`), crates/evm/src/handler.rs (`prepare_aa`, `prepare_keychain`, `access_key_id`).

## 9. Configurable-account signatures (0x05) at or before T13

Signature type 0x05 (`0x05 || rlp(ConfigurableAccountSignature)`) and key type 3 (`SignatureType::ConfigurableAccount`) belong to T14, which is out of scope. The reference decoder already accepts them, so a T13 client MUST reject them explicitly. At or before T13, a transaction is **invalid** if any of the following holds:

1. its `sender_signature` has type byte 0x05 (a payload of length ≠ 65 starting with 0x05);
2. its `sender_signature` is a Keychain V2 envelope whose inner signature has type byte 0x05 (inside a Keychain V1 envelope this is already a decode error);
3. any `tempo_authorization_list[i].signature` is, or is a keychain envelope wrapping, a 0x05 signature — this one is invalid **at every fork**, not only at or before T13;
4. its `key_authorization.signature` has type byte 0x05;
5. its `key_authorization.key_type` is 3 (`ConfigurableAccount`). (Key type values ≥ 4 are a decode error.)

A T13 client therefore does not need the internal layout of `ConfigurableAccountSignature`: whether the RLP after the 0x05 byte decodes or not, and whether its owner quorum verifies or not, the transaction cannot be in a valid block. For error reporting, the reference implementation rejects them at these points (an earlier, unrelated check of the 0x76 pipeline, such as the keychain version check, may reject the transaction first):

| Case | Where | Error |
|---|---|---|
| 0x05 bytes that are not valid `ConfigurableAccountSignature` RLP | decode | "Invalid configurable account signature RLP" |
| 0x05 inside Keychain V1 | decode | "configurable account access keys require keychain V2" |
| 1, 2 or 4 with an owner quorum that does not verify | sender recovery | recovery error |
| 3 | first validation step of the 0x76 pipeline | `ConfigurableAccount(InvalidSignatureContext)` |
| 5 | key-authorization validation | `ConfigurableAccount(UnsupportedContext)` |
| 1, 2 or 4 otherwise | configurable-role validation, before intrinsic gas | `ConfigurableAccount(UnsupportedContext)` |

Reference implementation: crates/evm/src/handler.rs (`prepare_aa`, `validate_key_authorization`), crates/evm/src/handler/configurable_account/mod.rs (`validate_configurable_roles`), crates/primitives/src/transaction/tt_authorization.rs (`recover_authority`).

## 10. Signing domains

Each signature signs a 32-byte digest determined by where it appears. Field encodings referred to below are those of [02-encoding.md](02-encoding.md), applied to the decoded, canonically re-encoded values (section 7).

### 10.1 0x76 sender signing hash

The 0x76 fields in order are `chain_id, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, calls, access_list, nonce_key, nonce, valid_before, valid_after, fee_token, fee_payer_signature, tempo_authorization_list, [key_authorization]`. `key_authorization` is present only when the transaction has one; when absent, no bytes are written for it.

```python
def sender_signing_hash(tx) -> bytes32:
    sponsored = tx.fee_payer_signature is not None
    fields = [
        rlp(tx.chain_id), rlp(tx.max_priority_fee_per_gas), rlp(tx.max_fee_per_gas),
        rlp(tx.gas_limit), rlp(tx.calls), rlp(tx.access_list), rlp(tx.nonce_key), rlp(tx.nonce),
        rlp(tx.valid_before) if tx.valid_before is not None else b"\x80",
        rlp(tx.valid_after)  if tx.valid_after  is not None else b"\x80",
        b"\x80" if sponsored or tx.fee_token is None else rlp(tx.fee_token),   # fee_token
        b"\x00" if sponsored else b"\x80",                                      # fee_payer_signature slot
        rlp(tx.tempo_authorization_list),
    ]
    if tx.key_authorization is not None:
        fields.append(rlp(tx.key_authorization))      # includes its canonical signature
    payload = b"".join(fields)
    return keccak256(bytes([0x76]) || rlp_list_header(len(payload)) || payload)
```

The fee-payer slot is the single raw byte `0x00` when the transaction is sponsored and `0x80` when it is not, so the sender commits to *whether* it is sponsored but not to the fee payer or (when sponsored) the fee token. The sender's own signature is not included.

### 10.2 Fee payer signing hash

```python
def fee_payer_signing_hash(tx, sender: Address) -> bytes32:
    fields = [ ...same first ten fields as 10.1...,
        rlp(tx.fee_token) if tx.fee_token is not None else b"\x80",   # always included
        rlp(sender),                       # 0x94 || 20-byte sender, in the fee_payer_signature slot
        rlp(tx.tempo_authorization_list),
    ]
    if tx.key_authorization is not None:
        fields.append(rlp(tx.key_authorization))
    payload = b"".join(fields)
    return keccak256(bytes([0x78]) || rlp_list_header(len(payload)) || payload)
```

`sender` is the recovered sender of section 11.2 (for a keychain signature, `user_address`).

### 10.3 Other domains

| Signature | Digest |
|---|---|
| Keychain V1 inner | the enclosing context digest `d` |
| Keychain V2 inner | `keccak256(0x04 \|\| d \|\| user_address)` (section 8.1) |
| EIP-7702 and Tempo authorization | `keccak256(0x05 \|\| rlp([chain_id, address, nonce]))` per EIP-7702 (`chain_id` uint256, `nonce` uint64) |
| Key authorization | `keccak256(rlp(KeyAuthorization))`, the unsigned KeyAuthorization list of [02-encoding.md](02-encoding.md), with no prefix byte |
| Ethereum transaction types | per EIP-155 (legacy), EIP-2930, EIP-1559, EIP-7702 |

The prefix bytes 0x04, 0x05, 0x76 and 0x78 keep the domains disjoint.

Reference implementation: crates/primitives/src/transaction/tempo_transaction.rs (`encode_for_signing`, `fee_payer_signature_hash`, `rlp_encode_fields`), crates/primitives/src/transaction/key_authorization.rs (`KeyAuthorization::signature_hash`), crates/primitives/src/transaction/tt_authorization.rs (`signature_hash`).

## 11. Sender and fee payer recovery

### 11.1 Ethereum transaction types

For Legacy, EIP-2930, EIP-1559 and EIP-7702 transactions the sender is recovered with section 4.2 over the digest defined by the transaction type's EIP (EIP-155 or pre-EIP-155 for legacy, see [06-transactions-and-fees.md](06-transactions-and-fees.md) for which chain-id forms are valid). The fee payer of such a transaction is its sender.

### 11.2 0x76 sender

```python
def recover_tempo_signature(sig: TempoSignature, d: bytes32) -> Address:
    if sig.is_secp256k1():  return secp256k1_recover(sig.r, sig.s, sig.y_parity, d)
    if sig.is_p256():       return recover_p256(sig, d)
    if sig.is_webauthn():   return recover_webauthn(sig, d)
    if sig.is_keychain():   return recover_keychain(sig, d)
    raise Invalid                         # 0x05 at <= T13: section 9

def recover_0x76_sender(signed_tx) -> Address:
    d = sender_signing_hash(signed_tx.tx)
    return recover_tempo_signature(signed_tx.sender_signature, d)
```

A recovery failure means the block is invalid. The sender is then subject to the stateful checks of [06-transactions-and-fees.md](06-transactions-and-fees.md), including the keychain checks of section 8.2.

### 11.3 0x76 fee payer

`fee_payer_signature` is either absent (encoded `0x80`) or an RLP list `[y_parity, r, s]` with `y_parity` the RLP integer 0 or 1 (no other value) and `r`, `s` RLP integers ([02-encoding.md](02-encoding.md)). It is always secp256k1.

```python
def fee_payer(signed_tx, sender: Address) -> Address:
    sig = signed_tx.tx.fee_payer_signature
    if sig is None:
        return sender
    try:
        payer = secp256k1_recover(sig.r, sig.s, sig.y_parity, fee_payer_signing_hash(signed_tx.tx, sender))
    except Invalid:
        raise InvalidTransaction("InvalidFeePayerSignature")
    if fork_active(T2, block_timestamp) and payer == sender:
        raise InvalidTransaction("SelfSponsoredFeePayer")
    return payer
```

- A fee-payer recovery failure is a validation failure of the transaction (not a decode or sender-recovery failure); the transaction is invalid. The all-zero placeholder `[0, 0, 0]` that wallets send to sponsorship services always fails recovery (`r = 0`).
- **From T2** a fee payer equal to the sender is invalid (TIP-1036). Before T2 it is valid and the sender pays.
- In the 0x76 validation order, the fee payer is checked after the keychain version, key-authorization, CREATE and value checks and before the fee and gas checks ([06-transactions-and-fees.md](06-transactions-and-fees.md)).

### 11.4 System transaction sentinel

A Legacy transaction whose signature is exactly `r = 0, s = 0, y_parity = 0` is the Tempo system-transaction sentinel: its sender is `0x0000000000000000000000000000000000000000` without any curve operation (and section 4.2 is not applied). Whether such a transaction is allowed, and where, is defined in [05-block-execution.md](05-block-execution.md) (one per block, last, before T4; none from T4). Any other Legacy signature is recovered normally.

Reference implementation: crates/primitives/src/transaction/envelope.rs (`TEMPO_SYSTEM_TX_SIGNATURE`, `recover_signer`), crates/primitives/src/transaction/tt_signed.rs (`recover_sender`), crates/primitives/src/transaction/tempo_transaction.rs (`recover_fee_payer`, `rlp_decode_fields`), crates/evm/src/transaction.rs, crates/evm/src/handler.rs (`prepare_aa`).

## 12. EIP-7702 authorizations

### 12.1 In EIP-7702 (0x04) transactions

Authorizations in Ethereum-type 0x04 transactions follow EIP-7702 unchanged: secp256k1 signatures `(y_parity, r, s)` over `keccak256(0x05 || rlp([chain_id, address, nonce]))`, recovered with section 4.2; an authorization whose authority cannot be recovered is skipped, not fatal.

### 12.2 In 0x76 transactions (`tempo_authorization_list`)

Each entry is `rlp([chain_id, address, nonce, signature])` with `signature` a `TempoSignature` byte string. An entry whose signature does not decode makes the transaction undecodable.

Transaction-level checks (any failure makes the transaction invalid):

1. No entry's signature may be, or wrap, a 0x05 signature (all forks; section 9).
2. A non-empty list forbids CREATE calls ([06-transactions-and-fees.md](06-transactions-and-fees.md)).
3. Every keychain-signed entry MUST pass the version check of section 8.4.

Applying the list (at the point of the 0x76 pipeline given in [06-transactions-and-fees.md](06-transactions-and-fees.md)), for each entry in order:

```python
def apply_tempo_authorizations(tx, state, chain_id):
    for auth in tx.tempo_authorization_list:
        if auth.signature.is_keychain():
            continue                               # T0+: keychain-signed entries are skipped
        if auth.chain_id != 0 and auth.chain_id != chain_id:
            continue
        if auth.nonce == 2**64 - 1:
            continue
        try:
            authority = recover_tempo_signature(auth.signature, eip7702_digest(auth))
        except Invalid:
            continue                               # bad signature: skip, not fatal
        state.warm(authority)
        code = state.code(authority)
        if code != b"" and not is_eip7702_delegation(code):
            continue
        if auth.nonce != state.nonce(authority):
            continue
        set_delegation(authority, auth.address)    # EIP-7702: code 0xef0100||address, or cleared if
                                                   # address == 0; authority nonce += 1
```

- An authorization signature can be secp256k1, P256 or WebAuthn; WebAuthn uses `base64url_nopad(eip7702_digest(auth))` as challenge.
- **Keychain-signed entries are skipped from T0**, so on mainnet they never delegate. They still decode, still pass the version check of section 8.4, and are still charged intrinsic gas (section 14). (Delegation through keychain-signed entries existed only in Moderato's pre-T0 era, which is out of scope.)
- The authority is warmed only once recovered, so entries skipped earlier warm nothing.
- Refund accounting per entry is in [06-transactions-and-fees.md](06-transactions-and-fees.md).

Reference implementation: crates/primitives/src/transaction/tt_authorization.rs, crates/evm/src/handler.rs (`apply_one_authorization`, `apply_authorization_list`, `prepare_aa`).

## 13. Key-authorization signatures

`key_authorization.signature` is an `AccountSignature`: a primitive secp256k1, P256 or WebAuthn signature (keychain envelopes are a decode error; 0x05 is invalid at or before T13, section 9). Its signer is recovered with sections 4–6 over `keccak256(rlp(KeyAuthorization))`; a WebAuthn key-authorization signature uses `base64url_nopad` of that digest as challenge. A recovery failure makes the transaction invalid (`KeyAuthorizationSignatureRecoveryFailed`). Who may sign a key authorization (the root before T6; the root or an admin access key from T6), the `chain_id` rule (0 is a wildcard before T1C, exact match from T1C) and the fork-gated fields are specified in [06-transactions-and-fees.md](06-transactions-and-fees.md).

Reference implementation: crates/primitives/src/transaction/key_authorization.rs (`SignedKeyAuthorization::recover_signer`, `authorizing_account`), crates/evm/src/handler.rs (`validate_key_authorization`).

## 14. Verification gas

The 21,000 base of a transaction already pays for one secp256k1 verification. Signature gas is part of intrinsic gas ([06-transactions-and-fees.md](06-transactions-and-fees.md)) and is the same at every fork from T0 to T13.

```python
def tokens(data: bytes) -> int:              # EIP-7623 tokens
    return sum(1 if b == 0 else 4 for b in data)

def primitive_verification_gas(sig) -> int:   # full cost
    if sig.is_secp256k1(): return 3_000
    if sig.is_p256():      return 8_000
    if sig.is_webauthn():  return 8_000 + 4 * tokens(sig.webauthn_data)   # whole webauthn_data

def primitive_intrinsic_extra(sig) -> int:    # cost beyond the ecrecover in the 21,000 base
    return primitive_verification_gas(sig) - 3_000

def tempo_signature_verification_gas(sig: TempoSignature) -> int:
    if sig.is_keychain():
        return primitive_intrinsic_extra(sig.inner) + KEYCHAIN_VALIDATION_GAS
    return primitive_intrinsic_extra(sig)
```

| Signature | Gas added |
|---|---|
| 0x76 sender: secp256k1 | 0 |
| 0x76 sender: P256 | 5,000 |
| 0x76 sender: WebAuthn | 5,000 + 16 per non-zero byte + 4 per zero byte of `webauthn_data` |
| 0x76 sender: Keychain V1 or V2 | the inner row + 3,000 |
| each `tempo_authorization_list` entry | `tempo_signature_verification_gas(entry.signature)` on top of the per-authorization cost of [06-transactions-and-fees.md](06-transactions-and-fees.md), including skipped keychain-signed entries (inner + 3,000) |
| `key_authorization.signature` | the **full** `primitive_verification_gas`: 3,000 / 8,000 / 8,000 + 4 × tokens(`webauthn_data`) |
| `fee_payer_signature` | 0 |
| Ethereum-type transactions and their EIP-7702 authorizations | 0 (as in Ethereum) |

The WebAuthn data charge covers all of `webauthn_data`, the 37-byte `authenticatorData` included. For example, a 32-byte non-zero rpIdHash, a non-zero flags byte and a zero signCount add `4 × (33 × 4 + 4 × 1) = 544` gas before `clientDataJSON` is counted.

> **Resolved conflict C-SIG-01**: docs and TIP-0001 charge WebAuthn calldata gas for clientDataJSON only; the code charges all of webauthn_data. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](conflicts.md#c-sig-01).

The configurable-account gas rules are T14-only and do not apply (section 9).

Reference implementation: crates/primitives/src/gas.rs, crates/primitives/src/transaction/tt_signature.rs (`verification_gas`, `intrinsic_verification_gas`), crates/evm/src/signature_gas.rs, crates/evm/src/handler.rs (`intrinsic_gas`, `calculate_key_authorization_gas`).

## 15. Fork summary

| Rule | Forks |
|---|---|
| secp256k1 (EIP-2 low-s), P256 (low-s), WebAuthn as specified here | all, T0–T13 |
| Lenient `v` / `pre_hash` decoding with canonical re-encoding | all |
| Keychain V1 (0x03) valid | before T1C |
| Keychain V2 (0x04) valid | from T1C |
| Inner keychain signature type must equal the stored key type | from T1 |
| Keychain-signed Tempo authorizations skipped | from T0 (all of mainnet) |
| Fee payer equal to sender is invalid | from T2 |
| 0x05 signatures and key type 3 invalid | all forks ≤ T13 (in authorization lists: all forks) |
| Signature verification gas schedule (section 14) | all |
