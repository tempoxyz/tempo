---
name: private-zone-rpc
description: Interact with authenticated private Tempo Zone RPC endpoints, derive X-Authorization-Token zone auth tokens, identify zone IDs and chain IDs from ZoneFactory or repo metadata, and debug 401/403 auth failures. Use when calling rpc-zone-*-private endpoints, web3_clientVersion, eth_chainId, zone_getZoneInfo, zone_getEncryptionKey, or any private zone JSON-RPC method that needs a zone auth token.
---

# Private Zone RPC

Use this skill for private Tempo Zone JSON-RPC endpoints that require
`X-Authorization-Token`.

## Auth Model

Private zone RPC authenticates every request before method dispatch, including
public methods like `web3_clientVersion`.

The token header is:

```text
X-Authorization-Token: <hex token>
```

The token is:

```text
<signature><version:1><zoneId:4><chainId:8><issuedAt:8><expiresAt:8>
```

Build the signing digest as:

```text
keccak256("TempoZoneRPC" padded with zeros to 32 bytes || token fields)
```

Sign that digest with `cast wallet sign --no-hash`. Do not use Ethereum signed
message prefixing.

## Quick Call

For zones created by the current repo tooling, prefer the built-in token helper
because it reads generated metadata:

```bash
export PRIVATE_KEY=<zone-wallet-private-key>
TOKEN=$(just zone-auth-token my-zone)
cast rpc web3_clientVersion \
  --rpc-url https://private-zone-rpc.example.com \
  --rpc-headers "X-Authorization-Token: $TOKEN"
```

When only the endpoint tuple is known, set `PRIVATE_KEY` in the environment and
use the helper script for one-off calls:

```bash
.codex/skills/private-zone-rpc/scripts/private_rpc_call.sh \
  https://private-zone-rpc.example.com \
  71 \
  421700071 \
  web3_clientVersion
```

The helper prints the JSON-RPC body on success and keeps the token out of logs.

## Reading The Active Encryption Key

Any authenticated caller can read the active sequencer encryption key at the
current Tempo L1 head:

```bash
cast rpc zone_getEncryptionKey \
  --rpc-url https://private-zone-rpc.example.com \
  --rpc-headers "X-Authorization-Token: $TOKEN"
```

The result is the portal's `encryptionKeyAtBlock` return value: `x`, a numeric
`yParity` of `2` or `3`, and the JSON-RPC quantity `keyIndex`. The endpoint
reads L1 directly so new keys are available before the Zone processes the
corresponding block.

## Finding Zone ID And Chain ID

Prefer exact metadata:

1. Read `generated/<name>/zone.json` for `zoneId`.
2. Read `generated/<name>/genesis.json` for `.config.chainId`; `zone.json` may
   also mirror the same value as `chainId`.
3. Resolve the ZoneFactory address from `generated/<name>/zone.json`,
   `ZONE_FACTORY`, or the repo default. In this repo, the default lives
   in `xtask/src/zone_utils.rs` as `MODERATO_ZONE_FACTORY`, and `docs/ZONES.md`
   mirrors it.
4. For this repo, derive missing chain IDs with
   `zone_primitives::constants::zone_chain_id`:

```text
if parent_chain_id == 4217:
    chain_id = 421700000 + zone_id
else if parent_chain_id == 42431:
    chain_id = 1424310000 + zone_id
else:
    chain_id = (parent_chain_id << 32) | zone_id
```

Production ranges reject exhaustion, and generic parents must be in `1..=1048574`.
`xtask create-zone` writes this value, and the node validates it at startup against
the connected parent chain and `ZonePortal.zoneId()`.

Query the factory counter:

```bash
cast call "$ZONE_FACTORY" \
  'zoneCount()(uint32)' \
  --rpc-url https://rpc.moderato.tempo.xyz
```

`zoneCount()` returns created zones. The internal next-zone counter is
`zoneCount + 1`.

## Debugging Status Codes

- `401` with empty body usually means the auth header is missing or the header
  name is wrong.
- `403` with empty body means a token was present but failed validation:
  malformed signature, wrong `zoneId`, wrong `chainId`, expired token, or token
  validity window too large.
- If `X-Authorization-Token` gives `403` but `zone-auth-token` or
  `Authorization: Bearer` gives `401`, the endpoint is using the expected
  header name and the tuple/signature is wrong.
