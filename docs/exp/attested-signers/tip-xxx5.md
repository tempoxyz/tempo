---
id: TIP-XXX5
title: Google Cloud Confidential Space Attestation
description: Attestation scheme 0x02 for the Attested Key Registry, which verifies Google Cloud Confidential Space attestation tokens signed with RS256 against keys that each policy lists.
authors: TBD
status: Draft
related: TIP-XXX1, TIP-XXX3
protocolVersion: TBD
---

# TIP-XXX5: Google Cloud Confidential Space Attestation

## Abstract

This TIP defines attestation scheme `0x02` for the [Attested Key Registry](./tip-xxx3.md). It verifies a Google Cloud Confidential Space attestation token, a JSON Web Token (JWT) that Google Cloud Attestation signs with RS256. The policy lists the attestation service's RSA keys as trust anchors. The measurement is a hash of the container image digest, and the token's nonce claim must contain the registration's binding.

RSA verification uses the existing modular exponentiation precompile pricing. JSON parsing adds a charge per byte, whose value awaits a benchmark.

## Motivation

Confidential Space runs one container image in a Confidential VM, whose memory is encrypted from the host. Google Cloud Attestation checks the VM and issues a token that names the image digest, the hardware, and whether debugging is possible. The workload can ask for a token with its own audience and nonces.

The token is an OpenID Connect style JWT, so the node verifies it with RSA and a JSON parser. Google publishes its signing keys and rotates them, so each policy lists the keys it trusts, and additions wait for the policy's delay.

## Assumptions

- Google Cloud Attestation signs a token only for a VM it verified, with claims that match that VM.
- The image digest identifies the container's code. A reproducible image build gives the same digest from the same source.
- Policy owners list only Google Cloud Attestation's current keys, and add new keys before Google starts using them.

---

# Specification

## Overview

A signer program in Confidential Space generates a program key, computes the registration's [binding](./tip-xxx3.md#binding), and requests a token with audience `ATTESTATION_AUDIENCE` and the binding as a nonce. It registers with the token and the RSA modulus that signed it. The scheme checks that the modulus is a policy anchor, verifies the signature, then checks the claims.

The authority boundary is the anchor and signature check. Only a token signed by a key the policy lists reaches the claim checks.

## Constants

| Name | Value | Notes |
|---|---|---|
| `SCHEME_CONFIDENTIAL_SPACE` | `0x02` | |
| `MAX_TOKEN_SIZE` | `8,192` bytes | |
| `RSA_MODULUS_SIZE` | `256` bytes | 2048-bit keys, exponent 65537 |
| `MAX_JSON_DEPTH` | `8` | |
| `ATTESTATION_ISSUER` | `"https://confidentialcomputing.googleapis.com"` | |
| `ATTESTATION_AUDIENCE` | `"tempo:attested-key-registry"` | |
| `CS_BASE_GAS` | TBD | Charged before decoding |
| `CS_BYTE_GAS` | TBD | Charged per token byte, before decoding |

## Document

```text
document = rlp([
    token,     // bytes, the JWT in compact serialization, ASCII
    modulus,   // bytes, exactly RSA_MODULUS_SIZE, big-endian
])
anchor = keccak256(modulus)
```

The RLP MUST be canonical, with exactly two fields and no trailing bytes.

## Verification

`verify(document, binding, policy, now)` runs these steps. Any failure makes `verify` fail, and the registry reverts with `InvalidAttestation`. The registry then checks that `anchor` is active ([TIP-XXX3](./tip-xxx3.md#registration)).

1. Decode `document`. Require `len(token) <= MAX_TOKEN_SIZE` and `len(modulus) == RSA_MODULUS_SIZE`, with the modulus's top bit set. Charge `CS_BASE_GAS + CS_BYTE_GAS * len(token)`.
2. Split `token` at its two `.` characters into `header_b64`, `payload_b64`, and `signature_b64`. Decode each as base64url without padding. Reject non-canonical encodings, including set unused bits in the last character.
3. Parse the header as JSON under the [JSON rules](#json-rules). Require `alg` to be `"RS256"`. If `typ` is present, require `"JWT"`. Ignore `kid`.
4. Require the signature to be 256 bytes and less than `modulus` as an integer. Charge the modular exponentiation precompile's price for a 256-byte base and modulus with exponent 65537, and SHA-256's price for `header_b64 "." payload_b64`. Require `signature^65537 mod modulus` to equal the EMSA-PKCS1-v1_5 encoding of `SHA-256(header_b64 "." payload_b64)` ([RFC 8017, section 9.2](https://www.rfc-editor.org/rfc/rfc8017#section-9.2)).
5. Parse the payload as JSON under the [JSON rules](#json-rules), and require every claim in [Claims](#claims).
6. Return:

   | Output | Value |
   |---|---|
   | `measurement` | `keccak256(image_digest)`, over the claim's UTF-8 bytes, such as `sha256:` followed by 64 hex digits |
   | `issued_at` | `iat` |
   | `expires_at` | `exp` |
   | `anchor` | `keccak256(modulus)` |

## Claims

| Claim | Requirement |
|---|---|
| `iss` | Equals `ATTESTATION_ISSUER` |
| `aud` | Equals `ATTESTATION_AUDIENCE`, as a string or a one-element array |
| `iat` | Integer, at most `now + 60` |
| `exp` | Integer, greater than `now` |
| `dbgstat` | Equals `"disabled-since-boot"` |
| `swname` | Equals `"CONFIDENTIAL_SPACE"` |
| `hwmodel` | One of `"GCP_AMD_SEV"`, `"GCP_AMD_SEV_SNP"`, `"GCP_INTEL_TDX"` |
| `submods.confidential_space.support_attributes` | Array containing `"STABLE"`, which marks a production Confidential Space image |
| `submods.container.image_digest` | String matching `sha256:[0-9a-f]{64}` |
| `eat_nonce` | A string, or an array of strings, containing `binding` as 64 lowercase hex digits without `0x` |

Claims not listed are ignored.

## JSON rules

The header and payload MUST be parsed with these rules. A document that a lax parser and a strict parser read differently is rejected.

- Valid UTF-8 and [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) JSON, with an object at the top level.
- No duplicate member names in any object.
- Nesting depth at most `MAX_JSON_DEPTH`.
- Strings are compared after decoding escapes. Numbers for `iat` and `exp` are non-negative integers without fraction or exponent, at most `type(uint64).max`.

## Trust anchors

Anchors are `keccak256(modulus)` of each RSA key that Google Cloud Attestation publishes. Policy owners add a new key with `proposeAnchor` before Google starts signing with it, since the addition waits for the policy's delay. Owners or guardians remove retired keys with `removeAnchor`.

## Gas

```text
cs_gas = CS_BASE_GAS + CS_BYTE_GAS * len(token)
       + modexp_price(256, 3, 256)       // exponent 65537 in 3 bytes
       + sha256_price(len(header_b64) + 1 + len(payload_b64))
```

The modular exponentiation and SHA-256 prices are those of the existing precompiles. `CS_BASE_GAS` and `CS_BYTE_GAS` are set from a benchmark of decoding and parsing a maximum-size token on the reference machine.

## Alternatives Considered

- **Listing anchors in consensus:** each Google key rotation would need a hardfork.
- **Including the project or service account in the measurement:** the measurement identifies code. Approved code enforces any deployment conditions itself ([TIP-XXX1](./tip-xxx1.md#signer-program-requirements)).
- **Accepting debug or non-production images:** their memory or launch policy is under the operator's control.

## Interfaces

This scheme adds no contract interface. Policies select it with `scheme = 0x02` in [`createPolicy`](./tip-xxx3.md#interfaces).

# Compatibility

| Integration | What changes |
|---|---|
| Wallet operators | Build the signer program as a reproducible container image, run it in Confidential Space, and request tokens with `ATTESTATION_AUDIENCE` and the binding as a nonce |
| Policy owners | Propose `keccak256(image_digest)` for each approved image, and keep the policy's anchors in step with Google's published keys |
| Monitors | Compare policy anchors with Google's published keys, and alert on an anchor Google does not publish |

# Observability

No new events. `AnchorProposed` and `AnchorRemoved` record key changes, and `KeyRegistered` records each measurement ([TIP-XXX3](./tip-xxx3.md#observability)). Nodes SHOULD export scheme `0x02` failures by step.

# Threat Model

[TIP-XXX1](./tip-xxx1.md#threat-model) owns the shared actors.

| Actor | Capability and trust | Boundary check and failure consequence |
|---|---|---|
| Google Cloud Attestation | Fully trusted for policies listing its keys | A compromised service or key can attest any image digest. Guardians remove the anchor and revoke keys. Owners rotate to a new key after the delay |
| Policy owner | Lists anchors | A malicious anchor lets its holder sign tokens for any digest after the delay. Monitors compare anchors with Google's published keys |
| VM operator | Runs images and requests tokens | Cannot change the image digest or the debug status. Step 5 rejects debug and non-production images |
| Sender of a crafted token | Exploits parser differences | Strict JSON rules, canonical base64url, and size and depth limits |

Residual risk: Confidential VM hardware flaws expose the program key until it expires or the guardian revokes keys.

# Invariants

- `verify` succeeds only for a token signed by a key whose modulus hash the policy lists as active.
- `verify` succeeds only if the token's nonce claim contains the binding.
- `verify` rejects debug and non-production images.
- The measurement depends only on the image digest.
- Gas is charged before decoding and before the RSA operation.

## Test Cases

- A production token through a full registration.
- Tokens with duplicate claims, deep nesting, non-canonical base64url, `alg` other than RS256, and a signature at or above the modulus.
- `dbgstat`, `swname`, `hwmodel`, and `support_attributes` each set to a rejected value.
- `iat` at, and one second past, `now + 60`, and `exp` at `now`.
- `eat_nonce` as a string, as an array, in uppercase hex, and with a `0x` prefix.

# Open Questions

- Confirm every claim name and value in [Claims](#claims) against a production token, including `eat_nonce`, `hwmodel` values, and `support_attributes`.
- Confirm the custom token request accepts `ATTESTATION_AUDIENCE` and a 64-character nonce, and the size of production tokens.
- Confirm Google Cloud Attestation signs with 2048-bit RSA keys and publishes new keys before using them, and how far ahead.
- Benchmark `CS_BASE_GAS` and `CS_BYTE_GAS`.
