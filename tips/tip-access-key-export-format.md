---
id: TIP-XXXX
title: Exportable Access Key Format
description: A standardized format for encoding access key private keys alongside signed key authorizations, enabling deferred onchain authorization.
authors: Jake Moxey
status: Draft
---

# TIP-XXXX: Exportable Access Key Format

## Abstract

TIP-XXXX defines a standardized encoding format for **exportable access keys** — a portable format that bundles an access key private key with a signed key authorization into a single string. This enables wallet export and account portability flows where the key authorization is deferred until the first meaningful onchain action, saving the user a separate authorization transaction and its associated fees.

## Motivation

Authorizing an access key onchain requires a dedicated transaction signed by the root account. For export/portability workflows — where a user exports an access key in one context and imports it into another — this creates friction:

- The user must pay gas to register the key onchain _before_ it can be used
- Two transactions are needed: one to authorize the key, one to perform the intended action

By bundling the signed key authorization _with_ the private key in a composite format, we solve both problems:

1. **Deferred authorization**: The key authorization can be submitted alongside the first real transaction (e.g., a token transfer), eliminating a separate authorization transaction and saving the user fees.
2. **Self-contained portability**: The composite key carries everything needed to use the access key — no indexer queries or onchain lookups required. The importing tool can derive the root account address, key permissions, and expiry directly from the encoded data.

## Terminology

| Term | Definition |
|------|------------|
| **Access key** | A delegated signing key (secp256k1, p256, or webAuthn) authorized to act on behalf of a root account |
| **Key authorization** | A signed authorization from the root account specifying the access key's address, type, expiry, spending limits, and chain scope |
| **Exportable access key** | The portable string defined by this TIP, containing both the private key and signed key authorization |
| **Deferred authorization** | Submitting the key authorization onchain as part of a future transaction rather than a separate, dedicated transaction |

## Specification

### Format

An exportable access key is a **base64url-encoded** binary payload with a `priv_` prefix.

The `priv_` prefix identifies the string as private key material. The underscore separates the prefix from the encoded payload.

```
key = priv_<base64url(payload)>

payload = version || private_key || signed_key_authorization
signed_key_authorization = rlp([
    [chain_id, key_type, key_id, expiry?, limits?],
    signature
])
```

| Field | Size | Description |
|-------|------|-------------|
| `version` | 1 byte | Format version. MUST be `0x01` for this specification. |
| `private_key` | 32 bytes | Private key. |
| `signed_key_authorization` | variable | RLP-encoded signed key authorization. |

## Rationale

### Bundling the key authorization

Without the key authorization bundled, the user would have to broadcast a redundant transaction before the first meaningful transaction, and the importing context would also need to either:
1. Query an indexer to find the root account and key permissions
2. Require the user to manually provide the root account address

Bundling makes the exportable access key fully self-contained.

### Base64url encoding

A typical exportable access key contains ~130–230 bytes of binary data. Hex encoding produces 260–460 characters; base64url produces ~175–310 characters. For QR codes, this difference matters, smaller payloads produce lower-density QR codes that are easier to scan.

### `priv_` prefix

The prefix serves three purposes:
1. **Identification**: Makes it immediately recognizable as private key material
2. **Safety**: Prevents accidental interpretation as other data formats
3. **Convention**: Follows the pattern of established prefixed formats (e.g., `xpub`, `npub`, `sk_live`)

### RLP encoding

RLP is already the canonical encoding for key authorizations in Tempo transactions.

## Security Considerations

1. **Sensitive material**: The exportable access key contains a raw private key. Implementations MUST treat it as secret material.

2. **No encryption**: This format does NOT encrypt the private key. It is intended for short-lived transfer contexts (clipboard copy, QR scan). For persistent storage, the key SHOULD be encrypted.

3. **Expiry enforcement**: The key authorization's `expiry` field limits the window of validity. Exportable access keys SHOULD set a reasonable expiry (e.g., 24–72 hours) to limit exposure if the key is leaked.

4. **Integrity check**: Decoders MUST verify that the derived access key address matches the `key_id` in the key authorization. This detects truncation, corruption, and tampering.
