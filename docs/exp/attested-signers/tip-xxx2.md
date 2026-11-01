---
id: TIP-XXX2
title: Attested Signatures
description: Adds signature type 0x06, which signs for an address derived from a policy and a user tag, using a program key that the Attested Key Registry holds as currently registered.
authors: TBD
status: Draft
related: TIP-XXX1, TIP-XXX3, TIP-0001, TIP-1011, TIP-1020, TIP-1045
protocolVersion: TBD
---

# TIP-XXX2: Attested Signatures

## Abstract

This TIP adds signature type `0x06`, the attested signature. Its address derives from a policy ID and a user tag, as a P256 address derives from a public key. An attested signature carries a P256 signature by a program key. The node accepts it only while the [Attested Key Registry](./tip-xxx3.md) records that key as current for the policy. Verification costs one P256 verification and two storage reads, and the signature is 206 bytes for current timestamps.

[TIP-XXX1](./tip-xxx1.md) explains how attested signers fit together. Attested signatures sign transactions and key authorizations, and contracts verify them for any hash through TIP-1020.

## Motivation

A signer program in a trusted execution environment authorizes an operation for a user, then needs to sign for that user's address. Existing signature types derive an address from the signing key, so every user would share the program key's single address. An attested signature separates the two: the program key proves that approved code signed, and the user tag selects which user's address it signed for.

The node cannot check how the user authorized the operation. It checks that the program key is registered, which proves the code is approved ([TIP-XXX3](./tip-xxx3.md#registration)). The approved code is responsible for signing for a user tag only as its authorization rules allow ([TIP-XXX1](./tip-xxx1.md#reference-authorization-profile)).

### Alternatives considered

- **The program key as the signer, with the user tag in calldata:** every user would share one address, and a program key rotation would move every account.
- **Measurement in the address:** every signer program upgrade would move every account.

## Assumptions

- [TIP-XXX3](./tip-xxx3.md) is active, with its storage layout fixed.
- Approved signer programs sign for a user tag only as their measured authorization rules allow ([TIP-XXX1](./tip-xxx1.md#assumptions)).
- Consensus keeps block timestamps close to real time.
- Configurable accounts (TIP-1114, in draft) are not required. Where they are active, an attested signature can approve as an owner.

---

# Specification

## Overview

This TIP owns the last step of the [attested signer lifecycle](./tip-xxx1.md#lifecycle), verification. Its input is a signature that a signer program made with a program key that [TIP-XXX3](./tip-xxx3.md) registered. Its outcome is the signer's address, or a rejection. The terms come from [TIP-XXX1](./tip-xxx1.md#terms).

An attested signature names a policy, a user tag, a program key, and an expiry, and carries the program key's signature. The node checks these things, in this order:

1. The encoding is canonical and the type is active.
2. The expiry is within the [validity window](#verification) at the block's timestamp.
3. The registry holds the program key as current for the policy.
4. The program key signed the [signed digest](#signed-digest) for this context.
5. The signer is the address derived from the policy ID and user tag.

The registry check is the authority boundary. A valid P256 signature from an unregistered key, or from a key registered for another policy, is rejected.

In the illustrative [TIP-XXX1 scenario](./tip-xxx1.md#sign-in-and-signing), the context is Alice's transaction, so the program key signs over that transaction's signing hash, and the sender is `attested_address(P, userTag)`. The same signature format serves the other [accepted contexts](#accepted-contexts) with a different context digest.

## Constants

| Name | Value | Notes |
|---|---|---|
| `SIGNATURE_TYPE_ATTESTED` | `0x06` | Next unassigned type after `0x05`. To confirm before review |
| `MAX_VALIDITY_WINDOW` | `600` seconds | Longest time before `valid_until` that a signature is accepted |
| `MAX_ATTESTED_SIGNATURE_SIZE` | `210` bytes | Largest canonical encoding, with a 9-byte `valid_until` |
| `COLD_SLOAD_COST` | `2,100` | |
| `P256_N` | `0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551` | Order of the P256 group |

## Encoding

```text
attested_signature = 0x06 || rlp([
    policy_id,     // bytes32, a TIP-XXX3 policy ID
    user_tag,      // bytes32
    program_key,   // bytes, exactly 64: x || y, 32-byte big-endian coordinates
    valid_until,   // uint64, seconds
    signature,     // bytes, exactly 64: r || s, 32-byte big-endian integers
])
```

- The RLP MUST be canonical, with exactly five fields and no trailing bytes. The signature MUST be at most `MAX_ATTESTED_SIGNATURE_SIZE` bytes.
- `program_key` MUST be an uncompressed P256 point that is on the curve and not the point at infinity.
- `r` and `s` MUST be in `[1, P256_N - 1]`, and `s` MUST be at most `P256_N / 2`.

Only `valid_until` varies in length, so a current signature is 206 bytes. A key authorization signed with one fits [TIP-1045](./tip-1045.md)'s 1,024-byte payment-lane bound.

## Address derivation

```text
attested_address = keccak256(0x06 || policy_id || user_tag)[12:]
```

The address does not depend on the program key, the measurement that registered it, the expiry, or the chain. Its 65-byte preimage cannot equal the 64-byte public-key preimage of a secp256k1 or P256 address ([TIP-0001](./tip-0001.md)). It is an ordinary account with no code.

## Signed digest

The program key signs:

```text
attested_digest = keccak256(
    "tempo:attested-signature" || d ||
    keccak256(rlp([policy_id, user_tag, program_key, valid_until]))
)
```

`d` is the context digest:

| Context | `d` |
|---|---|
| Transaction signature | Transaction signing hash ([TIP-0001](./tip-0001.md)) |
| Key authorization signature | Key authorization digest ([TIP-0001](./tip-0001.md)) |
| Configurable-account owner approval | The owner-approval digest defined by TIP-1114, where active |
| TIP-1020 `recover` and `verify` | The hash passed to the precompile |

The program key signs `attested_digest` with ECDSA over P256, with no further hashing. The ASCII domain keeps the digest distinct from other uses of the key. The digest covers every field except `signature`, so no other byte can change without the program key.

## Verification

```text
verify_attested_signature(signature, d, block):
    s = decode(signature)                                   // per Encoding, without curve operations

    require s.valid_until >= block.timestamp
    require s.valid_until <= block.timestamp + MAX_VALIDITY_WINDOW
    require program_key_current(s.policy_id, s.program_key)   // TIP-XXX3 node reads

    require p256_verify(s.program_key, attested_digest(d, s), s.signature)

    return attested_address(s.policy_id, s.user_tag)
```

The validity window is the time check above: `valid_until` is at least the block's timestamp and at most `MAX_VALIDITY_WINDOW` seconds after it.

- `program_key_current` reads registry storage at the transaction's position in the block ([TIP-XXX3](./tip-xxx3.md#node-reads)). A `revokeKeys`, `pause`, or `removeMeasurement` earlier in the same block applies.
- `p256_verify` checks that `program_key` is on the curve before verifying.
- Outside pool admission, such as sender recovery during block import, decoding and `p256_verify` MAY run before the registry read. The result MUST equal running every step in order.

Each failed check rejects the signature. A transaction with a rejected sender signature is invalid and does not enter a block, so no fee is charged and no nonce is consumed. A rejected key authorization signature makes its transaction invalid in the same way.

## Accepted contexts

An attested signature is accepted as:

- the signature of a Tempo transaction (type `0x76`) sent from its `attested_address`;
- the root signature of a key authorization for its `attested_address` ([TIP-0001](./tip-0001.md));
- an owner approval in a TIP-1114 configurable-account signature, where TIP-1114 is active;
- a signature checked by TIP-1020 `recover` and `verify` for any hash, as in [TIP-1020 verification](#tip-1020-verification).

It MUST be rejected:

- inside a keychain signature (`0x03` or `0x04`), including a configurable delegate's, because a program key is not an access key;
- as a fee payer signature, in subblock transactions, and in authorization lists;
- as an approval in TIP-1020 `verifyConfigurableAccount`, which reverts with `InvalidFormat`.

Before activation, type `0x06` MUST be rejected in every context.

Where TIP-1114 and TIP-1111 are active, each attested signature counts as one primitive signature toward their limits.

## TIP-1020 verification

TIP-1020 `verify(signer, hash, signature)` runs [Verification](#verification) with `d = hash`, against the registry state at the call, and returns `true` only if the attested address equals `signer`. A signature that fails the validity window, the registry check, or the P256 verification returns `false`. `recover(hash, signature)` returns the attested address under the same checks, and reverts with `InvalidSignature` where `verify` returns `false`. A non-canonical encoding reverts with `InvalidFormat` in both.

The precompile charges the P256 verification and the calldata cost of [Gas](#gas) before any check. The two registry reads charge their own cold storage cost. The result depends on current state: a signature that verifies now fails after `revokeKeys`, `pause`, `removeMeasurement`, or `valid_until`. Contracts MUST NOT cache a successful result past the call.

## Node behavior

- **Ordering.** Pools MUST finish decoding and time checks before any elliptic-curve operation, and SHOULD check fee affordability before the registry reads.
- **Revalidation.** Pools SHOULD revalidate pending transactions with attested signatures on `KeysRevoked`, `PolicyPaused`, and `MeasurementRemoved` for their policy, and evict them after `valid_until` or when their program key expires.
- **Caching.** Nodes MAY cache successful P256 verifications by `keccak256(attested_signature)` and `d`. The time checks and registry reads MUST run for each block.

## Gas

Wherever TIP-0001 or TIP-1114 charges a primitive signature's verification cost, an attested signature charges:

```text
attested_cost = 8,000                  // P256 verification, as TIP-0001 prices it
              + 2 * COLD_SLOAD_COST    // policy slot and program key record
              + calldata_gas(policy_id || user_tag || valid_until)
```

As a transaction signature, `attested_cost - 3,000` is added to the 21,000 base, as TIP-0001 does for P256. With non-zero bytes, `calldata_gas` of the 72 extra bytes is 1,152 gas, so a transaction signature adds at most 10,352 gas to the base. Zero bytes cost 4 gas, so a `valid_until` below 2^32 costs 48 gas less. TIP-1020 charges `attested_cost`.

## Activation

Activation is hardfork-gated, together with [TIP-XXX3](./tip-xxx3.md) and at least one attestation scheme. The owner-approval context applies once TIP-1114 is also active.

## Interfaces

Attested signatures add no new contract interface. The registry interface is in [TIP-XXX3](./tip-xxx3.md#interfaces).

# Compatibility

| Integration | What changes |
|---|---|
| SDKs, such as ox and Viem | Need `attested_address` and `attested_digest` derivation, `0x06` encoding and decoding, and builders for attested-signed transactions, key authorizations, and owner approvals |
| Wallets | Request attested signatures for transactions, key authorizations, owner approvals, and messages through the wallet operator. Access keys stay optional |
| RPC simulation and gas estimation | MUST apply the same checks and charges as block validation, and report which check failed |
| TIP-1020 callers | `verify` and `recover` accept attested signatures checked against the current registry state |
| Existing signature types | Unchanged |

Test vectors cover encodings, addresses, digests, and each rejection rule.

# Observability

No new events. Attested signatures are part of transactions, and registry events record which program keys are current ([TIP-XXX3](./tip-xxx3.md#observability)). Nodes SHOULD export rejections by reason, in the pool and in blocks.

# Threat Model

The local authority boundary is the registry read. [TIP-XXX1](./tip-xxx1.md#threat-model) owns the shared actors and attacks.

- **A key that is not registered, or registered for another policy,** cannot sign, because `program_key_current` names the policy.
- **Mempool observers** cannot reuse a signature for another digest or change any of its bytes, because the program key signs every other field.
- **A stolen program key** can sign for any user tag of its policy until the key expires, at most 600 seconds after registration. The policy guardian revokes it at once with `revokeKeys`.
- **Signatures created for a revoked key** fail in every later block, including later in the block that revokes it.
- **Proposer timestamps** can extend validity only within consensus bounds.

# Invariants

- An attested signature authorizes only the digest its program key signed, and no byte of it can change without the program key.
- An attested signature is valid only while the registry holds its program key as current for its policy, read at the transaction's position in the block.
- An attested signature is accepted only as a transaction signature, a key authorization signature, a configurable-account owner approval, or by TIP-1020 `verify` and `recover`.
- The address is independent of the program key, the measurement, the expiry, and the chain.
- Before activation, `0x06` is rejected in every context.

## Test Cases

- A first transaction whose key authorization carries an attested signature, and a transaction signed directly by one.
- A valid P256 signature from a key registered for another policy.
- `revokeKeys`, `pause`, and `removeMeasurement` earlier in the same block.
- `valid_until` at, and one second past, each of its bounds, and a program key at, and one second past, its expiry.
- Non-canonical RLP, a high `s`, an off-curve program key, and each rejected context.
