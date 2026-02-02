---
id: TIP-XXXX
title: Signature Verification Precompile
description: A precompile for verifying Tempo signatures onchain.
authors: Jake Moxey (@jxom)
status: Draft
related: TIP-1003
protocolVersion: TBD
---

# TIP-XXXX: Signature Verification Precompile

## Abstract

This TIP introduces a signature verification precompile that enables contracts to verify Tempo signature types (ie. secp256k1, P256, WebAuthn, etc) without relying on custom verifier contracts.

## Motivation

Tempo supports multiple signature schemes beyond standard secp256k1. Currently, contracts cannot verify Tempo  signatures onchain.

This precompile exposes Tempo's native signature verification to contracts.

## Specification

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

### Precompile Address

```sh
0x5165300000000000000000000000000000000000 # SIG(5[natur])E 
```

### Interface

```solidity
interface ISignatureVerifier {
    error InvalidSignature();
    error SignatureNotSupported();

    function verify(address signer, bytes32 hash, bytes calldata signature) external view returns (bool);
}
```

### Signature Encoding

The `signature` parameter MUST be encoded as follows:

| Type | Encoding | Length |
|------|----------|--------|
| secp256k1 | `r(32) \|\| s(32) \|\| v(1)` | 65 bytes |
| P256 | `0x01 \|\| r(32) \|\| s(32) \|\| x(32) \|\| y(32) \|\| prehash(1)` | 130 bytes |
| WebAuthn | `0x02 \|\| authData \|\| clientDataJSON \|\| r(32) \|\| s(32) \|\| x(32) \|\| y(32)` | 198–2048 bytes |

For backwards compatibility, secp256k1 signatures have no type prefix. All other signature types are prefixed with a type identifier byte.

### Verify Semantics

`verify(signer, hash, signature)` verifies that `signature` is a valid signature of `hash` by `signer`. Returns `true` if valid, reverts otherwise.

#### Parsing

1. If `signature.length == 0`, MUST revert with `InvalidSignature()`.
2. If `signature.length == 65`, parse as `secp256k1`.
3. Otherwise, the first byte is the type identifier:
   - `0x01`: `P256`
   - `0x02`: `WebAuthn`
   - `0x03`: `Keychain` (MUST revert with `SignatureNotSupported()`)
   - Other values: MUST revert with `InvalidSignature()`

#### `secp256k1` Verification

1. Extract `r`, `s`, `v` from signature bytes.
2. If `v < 27`, add 27 to normalize.
3. Call `ecrecover(hash, v, r, s)`.
4. If recovery fails or returns `address(0)`, MUST revert with `InvalidSignature()`.
5. If `recovered != signer`, MUST revert with `InvalidSignature()`.
6. Return `true`.

#### `P256` Verification

1. If `signature.length != 130`, MUST revert with `InvalidSignature()`.
2. Parse `r`, `s`, `x`, `y`, `prehash` from signature bytes.
3. Validate scalar ranges: `1 <= r < n` and `1 <= s < n`, where `n` is the P256 curve order. If invalid, MUST revert with `InvalidSignature()`.
4. Validate low-s: `s <= n/2`. If `s > n/2`, MUST revert with `InvalidSignature()`.
5. Validate public key point `(x, y)`:
   - Point MUST be on the P256 curve.
   - Point MUST NOT be the point at infinity.
   - If invalid, MUST revert with `InvalidSignature()`.
6. Verify P256 signature over `hash` (or the pre-hashed value if `prehash == 1`). If verification fails, MUST revert with `InvalidSignature()`.
7. Derive address as `address(keccak256(x || y)[12:])`.
8. If `derived != signer`, MUST revert with `InvalidSignature()`.
9. Return `true`.

#### `WebAuthn` Verification

1. If `signature.length < 198` or `signature.length > 2048`, MUST revert with `InvalidSignature()`.
2. Parse fixed fields from end: `r`, `s`, `x`, `y` (128 bytes total).
3. The remaining bytes after the type prefix and before the fixed fields are `authData || clientDataJSON`.
4. Validate `authData`:
   - Length MUST be exactly 37 bytes (when AT=0 and ED=0).
   - Flags byte (offset 32): UP (bit 0) or UV (bit 2) MUST be set.
   - AT (bit 6) MUST NOT be set.
   - ED (bit 7) MUST NOT be set.
   - If any validation fails, MUST revert with `InvalidSignature()`.
5. Validate `clientDataJSON`:
   - MUST be valid UTF-8 JSON.
   - Field `type` MUST equal `"webauthn.get"`.
   - Field `challenge` MUST equal `base64url(hash)` when decoded.
   - If field `crossOrigin` is present, it MUST be `false`.
   - If any validation fails, MUST revert with `InvalidSignature()`.
6. Validate scalar ranges and low-s as specified for P256. If invalid, MUST revert with `InvalidSignature()`.
7. Validate public key point as specified for P256. If invalid, MUST revert with `InvalidSignature()`.
8. Compute message hash: `sha256(authData || sha256(clientDataJSON))`.
9. Verify P256 signature over the message hash. If verification fails, MUST revert with `InvalidSignature()`.
10. Derive address as `address(keccak256(x || y)[12:])`.
11. If `derived != signer`, MUST revert with `InvalidSignature()`.
12. Return `true`.

#### `Keychain` Verification

Keychain signatures (type `0x03`) MUST revert with `KeychainNotSupported()`.

### Constants

| Name | Value |
|------|-------|
| P256 curve order (n) | `0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551` |
| P256 half order (n/2) | `0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8` |

### Gas Costs

Gas costs are TBD and will be determined during implementation.

## Rationale

### Excluding Keychain Signatures

Keychain (access key) signatures are intentionally excluded. Keychain signatures require validation beyond cryptographic verification: spending limit enforcement, expiry checks, and revocation status. These checks are performed during transaction validation and require state updates. Exposing keychain verification through this precompile would bypass these protections.

### Signer Parameter

The `signer` parameter is required because:
- For secp256k1, the signer can be recovered from the signature, but callers typically want to verify a specific expected signer.
- For P256 and WebAuthn, the public key is embedded in the signature, so the derived address must be compared against an expected signer.

This design allows a single function call to both verify the signature and confirm the signer, avoiding a two-step verify-then-compare pattern.

### Revert on Invalid Signatures

The function reverts on all invalid inputs rather than returning `false`. This provides:
- **Explicit errors**: Callers know exactly why verification failed (`InvalidSignature`, `KeychainNotSupported`, `UnknownSignatureType`).
- **Fail-fast behavior**: Invalid signatures are programming errors or attacks; silent `false` returns can mask bugs.
- **Simple success path**: If the call doesn't revert, the signature is valid.
