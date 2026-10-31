---
id: TIP-XXX4
title: AWS Nitro Enclaves Attestation
description: Attestation scheme 0x01 for the Attested Key Registry, which verifies AWS Nitro Enclaves attestation documents with the Zone verifier's Nitro attestation code.
authors: TBD
status: Draft
related: TIP-XXX1, TIP-XXX3, TIP-1096
protocolVersion: TBD
---

# TIP-XXX4: AWS Nitro Enclaves Attestation

## Abstract

This TIP defines attestation scheme `0x01` for the [Attested Key Registry](./tip-xxx3.md). It verifies an AWS Nitro Enclaves attestation document against the pinned AWS Nitro root certificate. The measurement is a hash of the enclave's PCR0, PCR1, and PCR2. The document's `user_data` must equal the registration's binding.

Verification reuses the Nitro attestation code that the Zone verifier uses for batch settlement, with the same gas charge: 40,000 gas plus 150,000 gas per P-384 signature, about 790,000 gas for a typical document.

## Motivation

AWS Nitro Enclaves run code in an isolated environment whose Nitro Security Module signs attestation documents. A document names the enclave's code through its platform configuration registers (PCRs) and carries data the enclave chooses. It chains to a fixed AWS root certificate, so verification needs no online issuer and no key list.

Tempo already verifies these documents in consensus for Zone settlement ([TIP-1096](./tip-1096.md)). This scheme reuses that code, so attested signers add no new parser or signature algorithm to consensus.

## Assumptions

- The AWS Nitro root certificate and the Nitro Security Module sign only genuine attestations.
- PCR0, PCR1, and PCR2 identify the enclave image, kernel, and application, as AWS defines them. A reproducible enclave image build gives the same PCRs from the same source.
- Debug-mode enclaves report PCR0, PCR1, and PCR2 as all zeros.

---

# Specification

## Overview

A signer program in a Nitro Enclave generates a program key, computes the registration's [binding](./tip-xxx3.md#binding), and asks its Nitro Security Module for a document with `user_data` set to the binding. The registry passes the document to this scheme's `verify`. The scheme checks the certificate chain and the document signature, derives the measurement from the PCRs, and checks the binding.

The authority boundary is the pinned root. Only a document that chains to it, through certificates valid at the block's timestamp, reaches the measurement and binding checks.

## Constants

| Name | Value | Notes |
|---|---|---|
| `SCHEME_NITRO` | `0x01` | |
| `MAX_NITRO_DOCUMENT_SIZE` | `24,576` bytes | The Nitro attestation code's `MAX_DOCUMENT_SIZE` |
| `NITRO_BASE_GAS` | `40,000` | Charged before parsing |
| `NITRO_SIGNATURE_GAS` | `150,000` | Charged per P-384 verification, before any verification |
| `AWS_NITRO_ROOT_DER` | The AWS Nitro Enclaves commercial-partition root certificate (G1), 533 bytes | SHA-256 `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`. Valid until 2049 |

## Verification

`verify(document, binding, policy, now)` runs these steps. Any failure makes `verify` fail, and the registry reverts with `InvalidAttestation`.

1. Require `len(document) <= MAX_NITRO_DOCUMENT_SIZE`. Charge `NITRO_BASE_GAS`.
2. Parse the document as a COSE_Sign1 Nitro attestation document.
3. Charge `NITRO_SIGNATURE_GAS * (len(cabundle) + 1)`. The pinned root is not verified, so the count is every other certificate plus the document.
4. Require `cabundle[0]` to equal `AWS_NITRO_ROOT_DER` byte for byte. Validate the certificate chain from it to the document's certificate, with each certificate valid at `now`. Verify every certificate signature and the document signature with P-384 and SHA-384.
5. Require PCR0, PCR1, and PCR2 to be present and 48 bytes each, and none of them to be all zeros.
6. Require `user_data` to be exactly 32 bytes and equal to `binding`.
7. Return:

   | Output | Value |
   |---|---|
   | `measurement` | `keccak256(PCR0 \|\| PCR1 \|\| PCR2)` |
   | `issued_at` | `floor(timestamp / 1000)`, since the document's `timestamp` is in milliseconds |
   | `expires_at` | `type(uint64).max`. Freshness comes from the registry's `MAX_ATTESTATION_AGE` |
   | `anchor` | Zero |

Steps 2 to 4 are the parsing and verification of `tempo-nitro-attestation` and the Zone verifier's `verify_attestation_with_root`, at commit [`b6d1615`](https://github.com/tempoxyz/tempo/tree/b6d1615b7a801d1c669824e2422f03024f0e1a67/crates/nitro-attestation). This scheme and the Zone verifier MUST use the same implementation, so a fix to one applies to both.

The scheme ignores the document's `public_key` and `nonce` fields, and every PCR other than 0, 1, and 2.

## Trust anchors

This scheme accepts no policy anchors. The root is pinned in consensus, and replacing it requires a hardfork. `createPolicy` and `proposeAnchor` revert with `InvalidAnchor` for a scheme `0x01` policy that lists an anchor.

## Gas

A document with `c` certificates in its `cabundle` costs:

```text
nitro_gas = NITRO_BASE_GAS + NITRO_SIGNATURE_GAS * (c + 1)
```

A typical document has four certificates in `cabundle` (the root and three intermediates), so it costs 40,000 + 150,000 × 5 = 790,000 gas. The registry adds storage for one key record, and the transaction pays calldata for the document, about 4 to 5 KB.

## Alternatives Considered

- **Measurement from PCR0 alone:** PCR0 covers the whole enclave image, but PCR1 and PCR2 separate the kernel and application, so a reviewer can check each against its build.
- **PCR8, the image-signing certificate:** would approve any image signed by one key, which makes that key a single point of failure.
- **Binding through `public_key` or `nonce`:** `user_data` is the field the Zone verifier binds, so both uses follow one pattern.
- **Caching intermediate certificates onchain:** would lower the cost, but the shared code verifies the full chain, and registration happens at most every few minutes for each signer program.

## Interfaces

This scheme adds no contract interface. Policies select it with `scheme = 0x01` in [`createPolicy`](./tip-xxx3.md#interfaces).

# Compatibility

| Integration | What changes |
|---|---|
| Wallet operators | Build the signer program as a reproducible Nitro enclave image, publish its PCR0, PCR1, and PCR2, and request documents with `user_data` set to the binding |
| Policy owners | Propose `keccak256(PCR0 \|\| PCR1 \|\| PCR2)` for each approved image |
| Zone verifier | Unchanged. It shares the attestation code with this scheme |

The `tempoxyz/tempo` repository already builds the Zone prover's enclave image reproducibly (`zones/docs/REPRODUCIBLE_BUILDS.md`). Signer programs can follow the same process.

# Observability

No new events. `KeyRegistered` records each measurement ([TIP-XXX3](./tip-xxx3.md#observability)). Nodes SHOULD export scheme `0x01` failures by step.

# Threat Model

[TIP-XXX1](./tip-xxx1.md#threat-model) owns the shared actors.

| Actor | Capability and trust | Boundary check and failure consequence |
|---|---|---|
| AWS Nitro root and Nitro Security Modules | Fully trusted | A compromised root or module can attest any PCRs, and so register keys for any policy using this scheme. Policy guardians pause. A hardfork disables the scheme |
| Enclave operator | Starts enclaves, chooses `user_data` for its own enclave only | Cannot change PCRs. A debug enclave reports zero PCRs, which step 5 rejects |
| Holder of another chain's or policy's document | Replays it | The binding names the chain, the registry, the policy, and the key |
| Sender of a malformed or oversized document | Spends validation work | Size is checked first, and gas is charged before parsing and before each signature check |

Residual risk: a Nitro hardware flaw exposes the program key until it expires or the guardian revokes keys.

# Invariants

- `verify` succeeds only for a document that chains to `AWS_NITRO_ROOT_DER` through certificates valid at `now`.
- `verify` succeeds only if `user_data` equals the binding.
- The measurement depends only on PCR0, PCR1, and PCR2.
- Gas is charged before parsing and before any signature verification.

## Test Cases

- A document from a test enclave whose `user_data` is a valid binding, through a full registration.
- A debug-mode document, a document with a missing or short PCR, and a `user_data` of 31 and 33 bytes.
- Each certificate at, and one second past, its validity bounds.
- A document whose `cabundle[0]` differs from the pinned root by one byte.

# Open Questions

- Confirm the usual `cabundle` length of production documents, which sets the typical registration cost.
