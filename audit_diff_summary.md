# Audit Diff Summary

**Commit Range:** `e310d91517464388a944ae300922e70fe02904c4` → `main`

**Scope:** `crates/` (excluding `crates/commonware`, `crates/commonware-node`, `crates/commonware-node-config`, `**/assets/**`, `**/tests/**`, `**/*test*`)

**Total:** 160 files, +32,715 / -19,276 lines (net +13,439)

---

## Precompiles (+4k net)

### stablecoin_exchange
- Remove system tx ([#1509](https://github.com/tempoxyz/tempo/pull/1509))
- Auto-create pairs on first order ([#985](https://github.com/tempoxyz/tempo/pull/985))
- Tick spacing enforcement ([#1084](https://github.com/tempoxyz/tempo/pull/1084))
- Quote rounding fixes - ceil vs floor ([#942](https://github.com/tempoxyz/tempo/pull/942))
- MIN/MAX_PRICE alignment with ticks ([#944](https://github.com/tempoxyz/tempo/pull/944))
- Overflow error handling ([#1124](https://github.com/tempoxyz/tempo/pull/1124))
- LCA optimization for multihop routing ([#1618](https://github.com/tempoxyz/tempo/pull/1618))
- Account for `is_bid` in `quote_exact_in` ([#1130](https://github.com/tempoxyz/tempo/pull/1130))
- Ensure orderbook best tick up-to-date ([#1075](https://github.com/tempoxyz/tempo/pull/1075))
- Set balance after `transfer_from` ([#1182](https://github.com/tempoxyz/tempo/pull/1182))

### tip_fee_manager
- Remove system tx ([#1537](https://github.com/tempoxyz/tempo/pull/1537))
- Pending fees validation ([#1106](https://github.com/tempoxyz/tempo/pull/1106))
- `reserve_liquidity` calculation fix ([#1277](https://github.com/tempoxyz/tempo/pull/1277))
- AMM liquidity tracker ([#1115](https://github.com/tempoxyz/tempo/pull/1115))
- Prevent reverts in FeeManager sys-tx ([#1056](https://github.com/tempoxyz/tempo/pull/1056))
- `set_fee_token` fix post-Moderato ([#1208](https://github.com/tempoxyz/tempo/pull/1208))

### account_keychain (NEW)
- Native keychain per account ([#598](https://github.com/tempoxyz/tempo/pull/598)) — +731 lines
- Handle refunds in keychain contract ([#1166](https://github.com/tempoxyz/tempo/pull/1166))
- Consistent handling of spending limits and expiry ([#1081](https://github.com/tempoxyz/tempo/pull/1081))

### tip20
- Blacklist enforcement on StablecoinExchange internal balances ([#1289](https://github.com/tempoxyz/tempo/pull/1289))
- `feeRecipient` support ([#1023](https://github.com/tempoxyz/tempo/pull/1023))
- Validate `is_tip20` in `from_address` post-AllegroModerato ([#1250](https://github.com/tempoxyz/tempo/pull/1250))
- Disable scheduled rewards ([#953](https://github.com/tempoxyz/tempo/pull/953))
- `delegateToDefaultV2` signature forgery fix ([#948](https://github.com/tempoxyz/tempo/pull/948))
- Reorder transfer events for mint/burn with memo ([#1479](https://github.com/tempoxyz/tempo/pull/1479))
- `invalidToken()` error ([#893](https://github.com/tempoxyz/tempo/pull/893))

### tip20_factory
- `tokenIdCounter` check in `isTIP20` ([#1234](https://github.com/tempoxyz/tempo/pull/1234))
- Skip quote token currency check for zero quote token ([#1246](https://github.com/tempoxyz/tempo/pull/1246))
- Validate deployed TIP20 tokens ([#1375](https://github.com/tempoxyz/tempo/pull/1375))

### tip403_registry
- Ensure registry not blacklisted ([#1028](https://github.com/tempoxyz/tempo/pull/1028))
- Add registry check on mint ([#1156](https://github.com/tempoxyz/tempo/pull/1156))

### path_usd (renamed from linking_usd)
- Uses default TIP20 logic ([#1015](https://github.com/tempoxyz/tempo/pull/1015))
- Create PathUSD through factory with `address(0)` as quote token ([#1168](https://github.com/tempoxyz/tempo/pull/1168))

### nonce
- Emit `NonceIncremented` event ([#1091](https://github.com/tempoxyz/tempo/pull/1091))

### storage
- API migration ([#1177](https://github.com/tempoxyz/tempo/pull/1177))
- Simplify storage internals ([#1105](https://github.com/tempoxyz/tempo/pull/1105))
- Thread-local context ([#1177](https://github.com/tempoxyz/tempo/pull/1177))
- New array type ([#1177](https://github.com/tempoxyz/tempo/pull/1177))
- Packing changes ([#1105](https://github.com/tempoxyz/tempo/pull/1105))
- OOB check in `Vec<T>::at(index)` ([#1469](https://github.com/tempoxyz/tempo/pull/1469))

### General
- Gas refund support ([#806](https://github.com/tempoxyz/tempo/pull/806))
- Disallow precompile static calls ([#1517](https://github.com/tempoxyz/tempo/pull/1517))
- ABI-encoded `UnknownFunctionSelector` error ([#941](https://github.com/tempoxyz/tempo/pull/941))
- Price bounds validation in `price_to_tick()` ([#939](https://github.com/tempoxyz/tempo/pull/939))

---

## Transaction Pool (+4.5k net)

| File | Description |
|------|-------------|
| `tt_2d_pool.rs` | New 2D nonce pool (+2,326 lines) ([#1006](https://github.com/tempoxyz/tempo/pull/1006)) |
| `tempo_pool.rs` | Pool wrapper (+718 lines) ([#1006](https://github.com/tempoxyz/tempo/pull/1006)) |
| `amm.rs` | AMM for fee estimation (+233 lines) ([#1115](https://github.com/tempoxyz/tempo/pull/1115)) |
| `best.rs` | Best transaction iterator (+274 lines) ([#1006](https://github.com/tempoxyz/tempo/pull/1006)) |
| `maintain.rs` | Pool maintenance (+140 lines) ([#1006](https://github.com/tempoxyz/tempo/pull/1006)) |
| `metrics.rs` | Pool metrics (+75 lines) ([#1006](https://github.com/tempoxyz/tempo/pull/1006)) |
| `validator.rs` | Fee payer blacklist check ([#1114](https://github.com/tempoxyz/tempo/pull/1114)), protocol nonces ([#1218](https://github.com/tempoxyz/tempo/pull/1218)) |

---

## REVM / Handler (+800 net)

- Gas refund support in precompiles ([#806](https://github.com/tempoxyz/tempo/pull/806))
- Fee token selection logic update ([#1022](https://github.com/tempoxyz/tempo/pull/1022))
- Disallow precompile static calls ([#1517](https://github.com/tempoxyz/tempo/pull/1517))
- Custom RPC revert errors ([#1073](https://github.com/tempoxyz/tempo/pull/1073))
- System tx gas handling ([#1441](https://github.com/tempoxyz/tempo/pull/1441))
- Paid subblocks fee recipient propagation ([#1086](https://github.com/tempoxyz/tempo/pull/1086), [#1018](https://github.com/tempoxyz/tempo/pull/1018))

---

## Primitives (+1.5k net)

### Renames
- `TxAA` → `TempoTransaction` ([#1171](https://github.com/tempoxyz/tempo/pull/1171))
- `aa_authorization.rs` → `tt_authorization.rs` ([#1171](https://github.com/tempoxyz/tempo/pull/1171))
- `aa_signature.rs` → `tt_signature.rs` ([#1171](https://github.com/tempoxyz/tempo/pull/1171))
- `aa_signed.rs` → `tt_signed.rs` ([#1171](https://github.com/tempoxyz/tempo/pull/1171))

### New
- `key_authorization.rs` — Keychain auth (+171 lines) ([#598](https://github.com/tempoxyz/tempo/pull/598))
- `nonce_key` support for 2D nonces ([#1122](https://github.com/tempoxyz/tempo/pull/1122))

### Fixes
- P256 high s check ([#1510](https://github.com/tempoxyz/tempo/pull/1510))
- Reject AT/ED flags in webauthn validation ([#1099](https://github.com/tempoxyz/tempo/pull/1099))
- ChainID validation in keyAuth ([#1078](https://github.com/tempoxyz/tempo/pull/1078))
- Serialize `keyId` for keychain signatures ([#1275](https://github.com/tempoxyz/tempo/pull/1275))
- Allow recovered AA authorization lists ([#1150](https://github.com/tempoxyz/tempo/pull/1150))

---

## Chainspec (+700 net)

- AllegroModerato hardfork ([#1193](https://github.com/tempoxyz/tempo/pull/1193))
- Allegretto hardfork ([#976](https://github.com/tempoxyz/tempo/pull/976))
- Dev genesis config ([#1179](https://github.com/tempoxyz/tempo/pull/1179))
- Allegretto time handling for Andantino ([#1154](https://github.com/tempoxyz/tempo/pull/1154))

---

## EVM / Block Building (+200 net)

- `engine.rs` — New engine abstraction ([#1086](https://github.com/tempoxyz/tempo/pull/1086))
- `block.rs` — Block building changes, system tx execution ([#1509](https://github.com/tempoxyz/tempo/pull/1509), [#1537](https://github.com/tempoxyz/tempo/pull/1537))
- Correctly calculate incentive gas ([#1092](https://github.com/tempoxyz/tempo/pull/1092))

---

## Payload Builder (+200 net)

- Duration metrics for system transactions ([#1058](https://github.com/tempoxyz/tempo/pull/1058))
- Gas used / gas per second metrics ([#1190](https://github.com/tempoxyz/tempo/pull/1190))
- Block time metric ([#1192](https://github.com/tempoxyz/tempo/pull/1192))
- Payload builder defaults ([#938](https://github.com/tempoxyz/tempo/pull/938))

---

## Node (+200 net)

### RPC
- Custom revert errors ([#1073](https://github.com/tempoxyz/tempo/pull/1073))
- `admin_validatorKey` endpoint ([#1205](https://github.com/tempoxyz/tempo/pull/1205))
- DEX/AMM pagination moved to alloy ([#965](https://github.com/tempoxyz/tempo/pull/965))

### Pool
- 2D pool integration ([#1006](https://github.com/tempoxyz/tempo/pull/1006))
- Reject invalid AA txs to prevent mempool DOS ([#1040](https://github.com/tempoxyz/tempo/pull/1040))
- Prevent short-lived AA txs from invalidating blocks ([#1055](https://github.com/tempoxyz/tempo/pull/1055))

---

## Alloy (+450 net)

- Random 2D nonce filler ([#1138](https://github.com/tempoxyz/tempo/pull/1138), [#1158](https://github.com/tempoxyz/tempo/pull/1158))
- Provider extensions ([#1138](https://github.com/tempoxyz/tempo/pull/1138))
- Receipt changes for `feePayer` ([#984](https://github.com/tempoxyz/tempo/pull/984))
- Request changes for `nonce_key` ([#1122](https://github.com/tempoxyz/tempo/pull/1122))

---

## New Crates

| Crate | Description |
|-------|-------------|
| `dkg-onchain-artifacts` | DKG on-chain artifact handling (+576 lines) ([#1039](https://github.com/tempoxyz/tempo/pull/1039)) |

---

## Other Crates

### contracts (+230 net, 14 files)
- ABI definitions for new `account_keychain` ([#598](https://github.com/tempoxyz/tempo/pull/598), [#1476](https://github.com/tempoxyz/tempo/pull/1476))
- Updated interfaces for tip20, tip_fee_manager, stablecoin_exchange, tip403_registry ([#1509](https://github.com/tempoxyz/tempo/pull/1509), [#1537](https://github.com/tempoxyz/tempo/pull/1537))
- Renamed `linking_usd` → `path_usd` ([#1015](https://github.com/tempoxyz/tempo/pull/1015))

### precompiles-macros (-600 net, 7 files)
- Layout and storable macro refactoring ([#1177](https://github.com/tempoxyz/tempo/pull/1177))
- New packing module ([#1105](https://github.com/tempoxyz/tempo/pull/1105))

### e2e (+1.1k net, 3 files)
- Execution runtime updates ([#1086](https://github.com/tempoxyz/tempo/pull/1086))
- Testing infrastructure changes ([#936](https://github.com/tempoxyz/tempo/pull/936))

### faucet (-100 net, 2 files)
- Use mint instead of transfer ([#1233](https://github.com/tempoxyz/tempo/pull/1233))
- Random 2D nonce filler ([#1232](https://github.com/tempoxyz/tempo/pull/1232))

### consensus (-60 net, 1 file)
- System tx removal refactoring ([#1509](https://github.com/tempoxyz/tempo/pull/1509), [#1537](https://github.com/tempoxyz/tempo/pull/1537))
- Validate blocktime is not in the future ([#1001](https://github.com/tempoxyz/tempo/pull/1001))

---

## Security-Critical Changes

1. **Blacklist enforcement** on StablecoinExchange internal balances ([#1289](https://github.com/tempoxyz/tempo/pull/1289))
2. **Disallow precompile static calls** ([#1517](https://github.com/tempoxyz/tempo/pull/1517))
3. **delegateToDefaultV2 signature forgery fix** ([#948](https://github.com/tempoxyz/tempo/pull/948))
4. **P256 high s check** ([#1510](https://github.com/tempoxyz/tempo/pull/1510))
5. **Reject AT/ED flags in webauthn** ([#1099](https://github.com/tempoxyz/tempo/pull/1099))
6. **ChainID validation in keyAuth** ([#1078](https://github.com/tempoxyz/tempo/pull/1078))
7. **Fee payer blacklist check** in mempool ([#1114](https://github.com/tempoxyz/tempo/pull/1114), [#1040](https://github.com/tempoxyz/tempo/pull/1040))
8. **TIP403 registry blacklist check** ([#1028](https://github.com/tempoxyz/tempo/pull/1028))
9. **OOB check in Vec::at()** ([#1469](https://github.com/tempoxyz/tempo/pull/1469))

---

## Hardfork-Gated Changes

### Moderato+
- Quote amount rounding (ceil instead of floor) ([#942](https://github.com/tempoxyz/tempo/pull/942))
- MIN/MAX_PRICE alignment with ticks ([#944](https://github.com/tempoxyz/tempo/pull/944))
- ABI-encoded `UnknownFunctionSelector` error ([#941](https://github.com/tempoxyz/tempo/pull/941))

### Allegretto+
- Auto-create DEX pairs on first order ([#985](https://github.com/tempoxyz/tempo/pull/985))
- Dynamic validator sets ([#1039](https://github.com/tempoxyz/tempo/pull/1039))
- Validate `is_tip20` in `from_address` ([#1250](https://github.com/tempoxyz/tempo/pull/1250))
- Skip quote token currency check for zero quote token ([#1246](https://github.com/tempoxyz/tempo/pull/1246))

### AllegroModerato+

**Stablecoin Exchange:**
- Remove system tx - orders committed immediately ([#1509](https://github.com/tempoxyz/tempo/pull/1509))
- `div_ceil` in exact-out bid calculations (rounding fix) ([#1509](https://github.com/tempoxyz/tempo/pull/1509))
- Deprecate `activeOrderId` and `pendingOrderId` selectors ([#1509](https://github.com/tempoxyz/tempo/pull/1509))
- Add `nextOrderId` selector ([#1509](https://github.com/tempoxyz/tempo/pull/1509))
- Enforce TIP20 blacklist on `transfer_from` for internal balances ([#1289](https://github.com/tempoxyz/tempo/pull/1289))
- Set balance after `transfer_from` ([#1182](https://github.com/tempoxyz/tempo/pull/1182))

**TIP20:**
- Validate `is_tip20` prefix in `from_address` ([#1250](https://github.com/tempoxyz/tempo/pull/1250))
- Skip quote token currency check for zero quote token ([#1246](https://github.com/tempoxyz/tempo/pull/1246))
- Event changes for mint/burn with memo ([#1479](https://github.com/tempoxyz/tempo/pull/1479))

**TIP20 Factory:**
- Enhanced `is_tip20` validation with `tokenIdCounter` check ([#1234](https://github.com/tempoxyz/tempo/pull/1234))

**Fee Manager:**
- Remove system tx ([#1537](https://github.com/tempoxyz/tempo/pull/1537))
- Prevent validator token change with pending fees ([#1106](https://github.com/tempoxyz/tempo/pull/1106))
- Changed fee collection flow (immediate vs end-of-block) ([#1059](https://github.com/tempoxyz/tempo/pull/1059))

**Account Keychain:**
- Event format changes (KeyAuthorized, KeyRevoked, SpendingLimitUpdated) ([#1416](https://github.com/tempoxyz/tempo/pull/1416))

**Block Building:**
- Reduced system transactions from 3 to 1 (only subblock signatures remain) ([#1509](https://github.com/tempoxyz/tempo/pull/1509), [#1537](https://github.com/tempoxyz/tempo/pull/1537))
