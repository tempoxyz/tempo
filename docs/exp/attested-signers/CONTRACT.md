# Attested Signers PoC: interface contract

Shared by three workstreams: the Tempo node (`tempoxyz/tempo`, branch `exp/attested-signers`), the Rust signer
service (`tempoxyz/id`, `services/attested-signer`), and the Tempo ID TypeScript integration (`tempoxyz/id`,
same branch). The TIP drafts in this folder (`tip-xxx1.md` … `tip-xxx5.md`) are the design. This file pins the exact
bytes and the PoC simplifications. If code and TIP disagree, this file wins for the PoC.

Everything here is DEV/EXPERIMENTAL. Nothing merges.

## Chain

- Localnet: `tempo node --dev`, chain id `1337`. All hardforks active at genesis (`dev.json`).
- Base: `tempoxyz/tempo` branch `joshie/configurable-activation-tests` at `179347b` (configurable accounts stack; the
  commit of Tempo ID's pinned image `ghcr.io/tempoxyz/tempo:sha-179347b`). Its latest fork is `T14`.
- `T14` gates everything below (active at genesis in `dev.json`). No new hardfork in the PoC.

## Registry precompile

- Address: `0xA77E570000000000000000000000000000000000` (`ATTESTED_KEY_REGISTRY_ADDRESS`).
- Solidity interface: `IAttestedKeyRegistry` from `tip-xxx3.md` → Interfaces. PoC MUST implement, with exactly those
  signatures/selectors: `createPolicy`, `computePolicyId`, `proposeMeasurement`, `cancelProposal`, `removeMeasurement`,
  `revokeKeys`, `pause`, `unpause`, `registerKey`, `policy`, `measurementActiveAt`, `keyValidUntil`. Others
  (`proposeAnchor`, `removeAnchor`, `setDelay`, `setGuardian`, `transferOwnership`, `anchorActiveAt`) MAY revert
  `Unauthorized()`/be omitted in the PoC. Events and errors as in the TIP (error `PolicyIsPaused`, not `PolicyPaused`).
- `policy_id = keccak256(abi.encode(creator, salt))`.
- Constants: `KEY_LIFETIME = 600`, `MAX_FUTURE_SKEW = 60`, `MAX_ATTESTATION_AGE = 300` (seconds).
- Registration checks and order: `tip-xxx3.md` → Registration. Record `{valid_until, epoch}` under
  `key_id = keccak256(policy_id ‖ x ‖ y)`.
- `binding = keccak256("tempo:attested-key" ‖ uint256(chainid) [32 bytes BE] ‖ registry address [20 bytes] ‖ policy_id [32] ‖ x [32] ‖ y [32])`.

## Attestation schemes

| Scheme | Root | Allowed chains |
|---|---|---|
| `0x01` Nitro | `AWS_NITRO_ROOT_DER` (already in `tempo-nitro-attestation`) | any |
| `0xFE` Nitro dev | `dev-root.der` in this folder (hex in `dev-root.der.hex`, SHA-256 `eef02ddde90ed0c4cbcdfa551b60b00ddbaae3824d929ecb9102ddff3f34e666`) | chain id `1337` only. Reject elsewhere with `UnknownScheme` |

Both use `tempo_nitro_attestation::{parse_attestation, verify_parsed}` with the scheme's root and the Zone verifier gas
(`40,000 + 150,000 × (cabundle.len() + 1)`), then `tip-xxx4.md` → Verification steps 5–7:
- PCR0, PCR1, PCR2 present, 48 bytes each, none all-zero.
- `user_data` exactly 32 bytes == `binding`.
- `measurement = keccak256(PCR0 ‖ PCR1 ‖ PCR2)`, `issued_at = timestamp_ms / 1000`, no expiry.

The dev root private key is `dev-root.key.pem` (PKCS#8, P-384). It is public and test-only. The signer's dev
attestation builds `root → intermediate (CA) → leaf` and signs the COSE_Sign1 document with the leaf key, in the shape
`crates/nitro-attestation` parses (`module_id`, `digest: "SHA384"`, `timestamp` ms, `pcrs`, `certificate`, `cabundle =
[root, intermediate]`, `public_key: null`, `user_data`, `nonce: null`; protected header alg ES384). Certificates:
ecdsa-with-SHA384, P-384, CA certs with critical basicConstraints CA:TRUE and keyUsage keyCertSign; leaf CA:FALSE with
digitalSignature; validity covering now. Validate generated documents with `tempo-nitro-attestation` in tests.

Dev PCRs (the dev signer reports these): `PCR0 = 0x01 × 48`, `PCR1 = 0x02 × 48`, `PCR2 = 0x03 × 48`.
`DEV_MEASUREMENT = keccak256(PCR0 ‖ PCR1 ‖ PCR2)`.

## Signature type 0x06

```
attested_signature = 0x06 ‖ rlp([policy_id: bytes32, user_tag: bytes32, program_key: bytes(64) x‖y,
                                 valid_until: uint64, signature: bytes(64) r‖s])
attested_digest    = keccak256("tempo:attested-signature" ‖ d ‖ keccak256(rlp([policy_id, user_tag, program_key, valid_until])))
attested_address   = keccak256(0x06 ‖ policy_id ‖ user_tag)[12:]
```

- `d` = key authorization signature hash (as `SignedKeyAuthorization` / `KeyAuthorization::signature_hash` computes it
  for other root signatures) or the transaction signing hash.
- Program key signs `attested_digest` with ECDSA P-256 directly (prehash = the 32-byte digest, no SHA-256). `s` low.
- Validity: `tip-xxx2.md` → Verification. `valid_until >= now`, `valid_until <= now + 600`, `program_key_current`
  (policy exists, not paused, record unexpired, record.epoch == policy.epoch), P-256 verify.
- Accepted as: transaction signature from `attested_address`, and key authorization root signature. Rejected inside
  keychain signatures, as fee payer, and by TIP-1020 (`InvalidFormat`).
- Gas: P-256 cost (8,000) + 2 × 2,100 + calldata gas of the 72 extra bytes, as `tip-xxx2.md` → Gas.

## Signer service HTTP API (`services/attested-signer`, Rust, axum)

JSON, hex strings `0x`-prefixed. Default port `8790`.

- `GET /v1/info` → `{ chainId, policyId, programKey: { x, y }, validUntil, measurement }`
- `POST /v1/otp/start` `{ email }` → `204`. Sends a 6-digit code (valid 10 min, 5 attempts).
- `POST /v1/otp/finish` `{ email, code, keyAuthorization }` → `{ address, userTag, signature, digest }`
  - `keyAuthorization`: `{ chainId, keyType: "p256" | "secp256k1" | "webAuthn", keyId, expiry, limits?: [{ token, limit }] }`
    (the fields the node's `KeyAuthorization` hashes). The signer computes `d` itself from these fields, so it signs
    exactly what it was shown.
  - `signature`: the full `0x06…` attested signature to put in the key authorization's `signature`.
- Dev only (feature `dev`): `GET /dev/codes/:email` → `{ code }` for tests.
- `user_tag = HMAC-SHA256(k, "tempo:user-tag:v1" ‖ "email:" ‖ lowercase(trim(email)))`, `k` from env `SIGNER_USER_TAG_KEY` (PoC).
- Email sender (compile-time): `cloudflare` (Email Service REST `POST https://api.cloudflare.com/client/v4/accounts/{account_id}/email/sending/send`,
  `Authorization: Bearer`, env `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_EMAIL_TOKEN`, `SIGNER_EMAIL_FROM`) or `dev`
  (stores codes in memory, served by `/dev/codes/:email`).
- Attestation (compile-time): `dev-attestation` (scheme `0xFE`, dev root) now; `nitro` (real NSM) later.
- Startup (dev): if the policy does not exist, create it with `SIGNER_ADMIN_KEY` (a funded localnet key), salt
  `keccak256("tempo-id:attested:dev")`, scheme `0xFE`, delay `0`, measurement `DEV_MEASUREMENT`. Then register a fresh
  program key and re-register every ~420 s.
- Env: `SIGNER_RPC_URL`, `SIGNER_ADMIN_KEY`, `SIGNER_USER_TAG_KEY`, `SIGNER_PORT`.

## Branches and PRs

- `tempoxyz/tempo`: branch `exp/attested-signers` off `179347b`, draft PR into `joshie/configurable-activation-tests`, titled `exp: attested signers PoC`.
- `tempoxyz/id`: branch `exp/attested-signers`, draft PR titled `exp: attested signers PoC`.
- Commit messages end with:

```
Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01D3nmWfxsYgSZCf4nZP5cZY
```

## Node implementation notes (`tempoxyz/tempo`, `exp/attested-signers`)

- Gating: the registry and type `0x06` are active from `T14` (no new hardfork). The registry gets its `0xEF`
  marker code at the first block of `T14`, as other precompiles do.
- Registry: every function of `IAttestedKeyRegistry` is implemented. Both Nitro schemes accept no anchors, so
  `proposeAnchor` reverts `InvalidAnchor`, `removeAnchor` reverts `NotListed`, and `anchorActiveAt` returns `0`.
  `createPolicy` reverts `AlreadyListed` for a duplicate initial measurement. `keyValidUntil` returns `0` unless the
  key is current (`program_key_current`).
- Scheme `0xFE` root: `tempo_nitro_attestation::NITRO_DEV_ROOT_DER`. Rust test helper:
  `tempo_nitro_attestation::testing::DevAttestation` (feature `test-utils`), with `DEV_PCRS`.
- `0x06` lives in both `AccountSignature::Attested` (key authorization root signature) and
  `TempoSignature::Attested` (transaction signature), as `tempo_primitives::transaction::AttestedSignature`.
  RLP field types: `policy_id` and `user_tag` are 32-byte strings, `program_key` and `signature` 64-byte strings,
  `valid_until` a canonical RLP integer. Encoded size is at most 210 bytes.
- `d` for a key authorization is `KeyAuthorization::signature_hash()`: `keccak256(rlp(KeyAuthorization))` over the
  same fields every other root signature signs. For a transaction it is the Tempo transaction signature hash.
- Decoding rejects trailing bytes, `r` or `s` outside `[1, n-1]`, and `s > n/2`. Sender recovery and key
  authorization recovery verify P256 (and that the key is on the curve). The handler then checks, at the
  transaction's position, for pool and block alike: `valid_until >= now`, `valid_until - now <= 600`, and
  `program_key_current`. A failure is `attested signature rejected: <reason>`.
- Rejected: inside keychain signatures (`0x03`/`0x04` decoding fails with
  `attested signatures cannot sign as access keys`), in EIP-7702 authorization lists, by TIP-1020
  (`InvalidFormat`), in Zone RPC auth tokens, and in zone transactions. Fee payer signatures are secp256k1 only.
- Gas: `8,000 + 2 × 2,100 + calldata_gas(policy_id ‖ user_tag ‖ valid_until as 8 bytes BE)`. As a transaction
  signature, `3,000` less is added to the 21,000 base. Zero bytes cost 4 gas, so a `valid_until` below `2^32`
  costs 48 gas less than the TIP's all-non-zero figure.
- Not built: pool revalidation on `KeysRevoked`/`PolicyPaused`/`MeasurementRemoved` (a pending transaction fails
  when it is executed), and RPC gas estimation for `0x06` beyond what the handler does for any signature.
