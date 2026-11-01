# Attested Signers PoC: interface contract

Shared by three workstreams: the Tempo node (`tempoxyz/tempo`, branch `exp/attested-signers`), the Rust signer
service (`tempoxyz/id`, `services/attested-signer`), and the Tempo ID TypeScript integration (`tempoxyz/id`,
same branch). The TIP drafts in this folder (TIP-1159 … TIP-1163) are the design. This file pins the exact
bytes and the PoC simplifications. If code and TIP disagree, this file wins for the PoC.

Everything here is DEV/EXPERIMENTAL. Nothing merges.

## Chain

- Localnet: `tempo node --dev`, chain id `1337`. All hardforks active at genesis (`dev.json`).
- Base: `tempoxyz/tempo` branch `joshie/configurable-activation-tests` at `179347b` (configurable accounts stack; the
  commit of Tempo ID's pinned image `ghcr.io/tempoxyz/tempo:sha-179347b`). Its latest fork is `T14`.
- `T14` gates everything below (active at genesis in `dev.json`). No new hardfork in the PoC.

## Registry precompile

- Address: `0x1161000000000000000000000000000000000000` (`ATTESTED_KEY_REGISTRY_ADDRESS`).
- Solidity interface: `IAttestedKeyRegistry` from TIP-1161 → Interfaces. PoC MUST implement, with exactly those
  signatures/selectors: `createPolicy`, `computePolicyId`, `proposeMeasurement`, `cancelProposal`, `removeMeasurement`,
  `revokeKeys`, `pause`, `unpause`, `setMaxKeyLifetime`, `registerKey`, `policy`, `measurementActiveAt`,
  `keyValidUntil`. Others
  (`proposeAnchor`, `removeAnchor`, `setDelay`, `setGuardian`, `transferOwnership`, `anchorActiveAt`) MAY revert
  `Unauthorized()`/be omitted in the PoC. Events and errors as in the TIP (error `PolicyIsPaused`, not `PolicyPaused`).
- `policy_id = keccak256(abi.encode(creator, salt))`.
- Constants: `KEY_SLOTS = 8`, `MAX_KEY_LIFETIME = 604,800` (7 days), `MAX_FUTURE_SKEW = 60`,
  `MAX_ATTESTATION_AGE = 300` (seconds).
- Key slots: each policy has `KEY_SLOTS` slots. `registerKey(policyId, slot, document, x, y, lifetime)` overwrites
  `slot` with `{key_hash, valid_until, epoch}` (one storage slot, `key_hash = bytes16(keccak256(x ‖ y))`), which ends
  the key the slot held. `valid_until = now + min(lifetime == 0 ? max : lifetime, max)`, where `max` is the policy's
  `maxKeyLifetime` (set at `createPolicy`, in `[1, MAX_KEY_LIFETIME]`; `setMaxKeyLifetime` decreases at once and
  increases after the policy's delay). `KeyRegistered` carries `key_id = keccak256(policy_id ‖ x ‖ y)` and `slot`.
- Registration checks and order: TIP-1161 → Registration (`InvalidSlot` for `slot >= KEY_SLOTS`, after the scheme).
- `binding = keccak256("tempo:attested-key" ‖ uint256(chainid) [32 bytes BE] ‖ registry address [20 bytes] ‖ policy_id [32] ‖ slot [1] ‖ x [32] ‖ y [32] ‖ lifetime [8 bytes BE])`. The
  binding names `lifetime`, so a copy of a registration cannot shorten the key.

## Attestation schemes

| Scheme | Root | Allowed chains |
|---|---|---|
| `0x01` Nitro | `AWS_NITRO_ROOT_DER` (already in `tempo-nitro-attestation`) | any |
| `0xFE` Nitro dev | `dev-root.der` in this folder (hex in `dev-root.der.hex`, SHA-256 `eef02ddde90ed0c4cbcdfa551b60b00ddbaae3824d929ecb9102ddff3f34e666`) | chain id `1337` only. Reject elsewhere with `UnknownScheme` |

Both use `tempo_nitro_attestation::{parse_attestation, verify_parsed}` with the scheme's root and the Zone verifier gas
(`40,000 + 150,000 × (cabundle.len() + 1)`), then TIP-1162 → Verification steps 5–7:
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
attested_signature = 0x06 ‖ rlp([policy_id: bytes32, user_tag: bytes32, slot: uint8, program_key: bytes(64) x‖y,
                                 valid_until: uint64, signature: bytes(64) r‖s])
attested_digest    = keccak256("tempo:attested-signature" ‖ d ‖ keccak256(rlp([policy_id, user_tag, slot, program_key, valid_until])))
attested_address   = keccak256(0x06 ‖ policy_id ‖ user_tag)[12:]
```

- `d` = key authorization signature hash (as `SignedKeyAuthorization` / `KeyAuthorization::signature_hash` computes it
  for other root signatures) or the transaction signing hash.
- Program key signs `attested_digest` with ECDSA P-256 directly (prehash = the 32-byte digest, no SHA-256). `s` low.
- Validity: TIP-1160 → Verification. `valid_until >= now`, `valid_until <= now + 600`, `program_key_current`
  (policy exists, not paused, `slot < KEY_SLOTS`, the slot holds this key, unexpired, slot epoch == policy epoch),
  P-256 verify.
- Accepted as: transaction signature from `attested_address`, key authorization root signature, configurable-account
  owner approval, and in TIP-1020. Rejected inside keychain signatures and as fee payer.
- Gas: P-256 cost (8,000) + 2 × 2,100 + calldata gas of the 73 extra bytes (`policy_id ‖ user_tag ‖ slot ‖
  valid_until`), as TIP-1160 → Gas.

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
  `createPolicy` reverts `AlreadyListed` for a duplicate initial measurement. `keyValidUntil(policyId, x, y)` reads
  every slot and returns the `valid_until` of the one that holds the key as current, or `0`.
- Scheme `0xFE` root: `tempo_nitro_attestation::NITRO_DEV_ROOT_DER`. Rust test helper:
  `tempo_nitro_attestation::testing::DevAttestation` (feature `test-utils`), with `DEV_PCRS`.
- `0x06` lives in both `AccountSignature::Attested` (key authorization root signature) and
  `TempoSignature::Attested` (transaction signature), as `tempo_primitives::transaction::AttestedSignature`.
  RLP field types: `policy_id` and `user_tag` are 32-byte strings, `slot` a canonical RLP integer below 8,
  `program_key` and `signature` 64-byte strings, `valid_until` a canonical RLP integer. Encoded size is at most 211
  bytes (207 with a 4-byte `valid_until`).
- `d` for a key authorization is `KeyAuthorization::signature_hash()`: `keccak256(rlp(KeyAuthorization))` over the
  same fields every other root signature signs. For a transaction it is the Tempo transaction signature hash.
- Decoding rejects trailing bytes, `slot >= 8`, `r` or `s` outside `[1, n-1]`, and `s > n/2`. The handler checks every
  attested signature of the transaction (sender, key authorization, owner approvals) at its position, for pool
  and block alike: `valid_until >= now`, `valid_until - now <= 600`, then `program_key_current`. It runs these
  before key authorization recovery and owner quorum checks, so every P256 verification in the handler follows
  the registry read. A failure is `attested signature rejected: <reason>`.
- Pool ordering (TIP-1160 "Ordering"): pool recovery (`try_recover`, `try_recover_with_cache`,
  `recover_raw_transaction`, `recover_raw_transaction_with_cache`) derives a `0x06` sender as
  `attested_address(policy_id, user_tag)` without a curve operation and never puts it in the sender recovery
  cache that block import reads. The validator then runs, in order: activation and validity window of every
  attested signature (before building the transaction environment, so before the secp256k1 fee payer
  recovery), the handler (registry reads, then key authorization and owner approval P256), and last the
  sender's P256 verification (`P256 signature verification failed`). Block import still recovers senders,
  verifying a `0x06` sender's P256 first, as the TIP allows outside pool admission. Not covered: a transaction
  that reaches the pool already recovered (`eth_sendTransaction`, reorg reinjection) was verified earlier and
  is verified again.
- TIP-1020 (`0x5165…`, from `T14`; supersedes "rejected by TIP-1020" above): `verify(signer, hash, sig)` returns
  `true` iff the `0x06` signature decodes canonically, `now <= valid_until <= now + 600`, `program_key_current` holds
  at the call, P256 verifies over `attested_digest(d = hash)`, and `attested_address == signer`; otherwise `false`.
  `recover(hash, sig)` returns the attested address under the same checks and reverts `InvalidSignature` otherwise.
  Non-canonical bytes revert `InvalidFormat`. Gas: P256 8,000 + calldata of the 72 extra bytes, charged before any
  check, plus the two registry reads at their storage cost. `verifyKeychain` and `verifyKeychainAdmin` reject
  `0x06` (`InvalidFormat`). `verifyConfigurableAccount` accepts `0x06` owner approvals: each is charged as a
  standalone `0x06` (with the other approvals, before any check, and its two registry reads at their storage cost),
  and the call returns `false` if one fails the window or `program_key_current`. Its P256 is verified with the
  other approvals; a failure reverts `InvalidSignature`, as for other owners.
- Rejected: inside keychain signatures (`0x03`/`0x04` decoding fails with
  `attested signatures cannot sign as access keys`), including as an owner approval of a configurable delegate's
  `0x05` signature inside a keychain signature (same decoding error; the handler also rejects one built in memory
  with `attested approval inside a keychain signature`), in EIP-7702 authorization lists, in Zone RPC auth tokens, and
  in zone transactions. Fee payer signatures are secp256k1 only.
- Gas: `8,000 + 2 × 2,100 + calldata_gas(policy_id ‖ user_tag ‖ valid_until as 8 bytes BE)`. As a transaction
  signature, `3,000` less is added to the 21,000 base. Zero bytes cost 4 gas, so a `valid_until` below `2^32`
  costs 48 gas less than the TIP's all-non-zero figure.
- Configurable account owners (`0x05`): an attested signer is an ordinary owner entry whose `owner` is its
  `attested_address(policy_id, user_tag)`; configurations carry no owner kind on this base (owners are
  `{address, weight}`), so configs and commitments are unchanged. In the approvals list of a `0x05` signature, each
  entry is an RLP byte string of typed signature bytes; an attested approval is `0x06 ‖ rlp([...])`, exactly the
  standalone `0x06` bytes, next to the existing secp256k1 (65 bytes) / `0x01` P256 / `0x02` WebAuthn entries.
  The program key signs `attested_digest(d)` with `d = configurable_account_digest(inner, account, version)`
  (`keccak256("tempo:configurable-account:signature" ‖ inner ‖ account ‖ version as 8 bytes BE)`, where `inner` is
  the transaction signature hash, the key authorization hash, or the keychain V2 hash, as for other owners).
  Approvals stay sorted by recovered owner address. Each counts as one signature toward the 8-approval limit and
  costs the standalone `0x06` gas. The handler checks its validity window and registry state at the transaction's
  position. TIP-1020 `verifyConfigurableAccount` accepts attested approvals, as above.
- Not built: pool revalidation on `KeysRevoked`/`PolicyPaused`/`MeasurementRemoved`/`KeyRegistered` (a pending
  transaction fails when it is executed).

## RPC

JSON form of a `0x06` signature, wherever a transaction, a block, or a request carries one (the transaction's
`signature`, `keyAuthorization.signature`):

```json
{ "type": "attested", "policyId": "0x…32 bytes", "userTag": "0x…32 bytes", "slot": "0x0",
  "programKey": "0x…64 bytes (x ‖ y)", "validUntil": "0x6b49d458", "signature": "0x…64 bytes (r ‖ s)" }
```

`slot` and `validUntil` are hex quantities. A `0x05` signature stays one RLP hex string, so its attested approvals
are the standalone `0x06` bytes inside it.

Pending transactions. `txpool_content`, `txpool_contentFrom`, `txpool_inspect`, and `txpool_status` list a
pending `0x06`-signed transaction under its attested address, by nonce, in the same form as
`eth_getTransactionByHash` with `blockHash`, `blockNumber`, and `transactionIndex` null:

```json
{ "pending": { "0x<attested address>": {
    "0": { "type": "0x76", "from": "0x<attested address>", "nonce": "0x0", "nonceKey": "0x0", "calls": [ … ],
           "keyAuthorization": null, "signature": { "type": "attested", "policyId": "0x…", … } },
    "1": { "type": "0x76", "nonce": "0x1",
           "keyAuthorization": { "keyId": "0x…", "keyType": "p256", …,
                                 "signature": { "type": "attested", "policyId": "0x…", … } },
           "signature": { "version": "v2", "userAddress": "0x<attested address>", "keyId": "0x…",
                          "signature": { "type": "p256", … } } } } },
  "queued": {} }
```

`txpool_inspect` summarizes each by its first call: `"0": "0x<to>: 0 wei + 3000000 gas × 20000000000 wei"`.

Simulation before the program key signs. `eth_estimateGas`, `eth_call`, `eth_createAccessList`,
`eth_fillTransaction`, `debug_traceCall`, and `eth_simulateV1` / `tempo_simulateV1` take, on the request:

| Field | Models |
|---|---|
| `attestedSimulation` | The sender's `0x06` signature. `from` must equal its attested address. Excludes `keyId` and `configurableAccountSimulation` |
| `keyAuthorizationAttestedSimulation` | The `0x06` root signature of the attached `keyAuthorization`. Excludes `keyAuthorizationSimulation` |
| `configurableAccountSimulation.approvals[].attested` | A `0x06` owner approval. The owner must equal its attested address. Excludes `keyType` and `keyData` |

Each is `{ policyId, userTag, slot, programKey, validUntil? }`. The node builds a placeholder `0x06` signature with
those fields (`r = s = 1`), reads the registry for `slot` at the block as block validation does, and charges the
same gas, but skips the P256 verification, as it skips other placeholder signatures. `validUntil` defaults to the
block timestamp plus 300 (`eth_simulateV1`: the node's clock plus 300). Pass the value the signature will carry
for an exact estimate: each zero byte of it costs 12 gas less. After `revokeKeys`, each method fails with
`attested signature rejected: program key is not current`, as `eth_sendRawTransaction` does.

## Deviations from the TIPs

- Activation: the PoC gates everything on T14. The TIPs leave the hardfork open.
- Scheme `0xFE` (Nitro dev root, chain 1337 only) is PoC-only. Scheme `0x02` (TIP-1163) is not implemented.
