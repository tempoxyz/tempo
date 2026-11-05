# TIP-20 tokens, TIP20Factory and TIP20ChannelReserve

This chapter specifies the native TIP-20 token precompile, the TIP20Factory precompile that creates tokens, and the TIP20ChannelReserve precompile (TIP-1034) that holds payment-channel deposits in TIP-20 tokens. It covers every rule that affects the validity or post-state of a Tempo mainnet block from genesis through T13: storage layout, ABI, check order, the gas-relevant sequence of storage operations, events and their order, and every fork-dependent change.

Related chapters:

- [00-framework.md](00-framework.md): precompile routing, calldata input cost, selector gating, ABI decoding strictness, static-call and delegate-call rules, the storage model (slot assignment, packing, mapping keys, strings), and the gas cost of every primitive operation used below.
- [tip403.md](tip403.md): TIP-403 policies (`isAuthorizedAs`, roles `sender`, `recipient`, `mintRecipient`), the T9 token-policy binding (TIP-1092), receive policies and the ReceivePolicyGuard (TIP-1028), and the AddressRegistry for virtual addresses (TIP-1022).
- [account-keychain.md](account-keychain.md): access-key spending limits (`authorize_transfer`, `authorize_approve`, `refund_spending_limit`), the SignatureVerifier (TIP-1020) and StorageCredits (TIP-1060).
- [fee-manager.md](fee-manager.md) and [stablecoin-dex.md](stablecoin-dex.md): the callers of the internal hooks in §9.
- [../05-block-execution.md](../05-block-execution.md): installation of the 0xEF code marker at fork boundaries, including TIP20ChannelReserve at T5.
- [../04-state-and-genesis.md](../04-state-and-genesis.md): genesis allocation, including the genesis TIP-20 accounts.

## 1. Conventions

### 1.1 Forks

"From Tn" means the rule applies when fork Tn is active, and "Before Tn" when it is not, where fork F is active iff `header.timestamp >= F's activation time` as defined in [../01-chain-and-forks.md](../01-chain-and-forks.md). "Genesis" means every block. Inside pseudocode, `is_active(Tn)` is that predicate for the block being executed.

### 1.2 Operation notation

Gas is never stated as a total. Each procedure lists the metered operations it performs, in order. An implementation MUST perform the same operations in the same order, because the order fixes the gas charged before any revert and the TIP-1060 storage-credit effects (T7+). The cost and failure behaviour of each primitive are defined in [00-framework.md](00-framework.md):

| Notation | Meaning |
|---|---|
| `ACCOUNT_READ(a)` | ([00-framework.md](00-framework.md) §7.2) Metered account access of `a` (warm read cost, plus the cold-account surcharge if `a` is cold; from T4 the warm part is charged before loading). Used by the TIP-20 initialization check and by `is_tip20`. |
| `SLOAD(c, s)` | Metered storage read of slot `s` of contract `c`. When `c` is omitted it is the contract the procedure belongs to. |
| `SSTORE(c, s, v)` | Metered storage write (including, from T7, the TIP-1060 credit hook and, from T12, the call-stipend sentry). |
| `SINC(s, d)` / `SDEC(s, d)` | `SLOAD(s)` then `SSTORE(s, old ± d)`. On overflow (SINC) or underflow (SDEC) no write happens and the error stated at the call site is raised. |
| `RMW(s, field)` | Packed access ([00-framework.md](00-framework.md) §6.2): write of a field that shares slot `s` with another field: `SLOAD(s)`, replace the field's bytes, `SSTORE(s, new)`. |
| `STR_READ(s)` / `STR_WRITE(s, x)` | ([00-framework.md](00-framework.md) §6.7) Solidity string read and write at base slot `s` (short form for ≤ 31 bytes, long form otherwise; from T5 a write first reads the base slot to clear a stale long-string tail). |
| `KECCAK(n)` | Metered keccak-256 over `n` bytes. Mapping-slot derivation and the factory's address derivation are **not** metered. |
| `ECRECOVER` | 3,000 gas, charged before the signature is examined. |
| `TLOAD(s)` / `TSTORE(s, v)` | Metered transient-storage access (100 gas each). |
| `LOG(event)` | Log emission from the contract the procedure belongs to, with the standard log cost for its topics and data. |
| `SET_CODE(a, 0xEF)` | Install the 1-byte code `0xEF` at `a`, charging the code-deposit cost for 1 byte. |
| `fail(E)` | Revert with ABI-encoded error `E`. Any state change made earlier in the frame is discarded by the revert. |

Arithmetic overflow and underflow that is not mapped to a named error reverts with Solidity `Panic(uint256)` (selector `0x4e487b71`) with code `0x11`; this document writes it as `fail(Panic(0x11))`.

"Revert" always means the precompile frame reverts with the stated return data; the EVM frame semantics (gas returned to the caller, state rollback) are as in [00-framework.md](00-framework.md).

### 1.3 Internal calls

Several procedures below are invoked natively by another precompile or by the transaction handler, not through ABI dispatch (§9). Such a call:

- performs no input-cost charge, no selector dispatch and no TIP-20 initialization check (§3.2);
- runs in the gas context of the calling precompile frame (or of the handler, as the calling chapter says);
- reads and writes the token's storage with the same metered operations, but does not perform `ACCOUNT_READ` on the token. Touching another contract's storage warms that account without an account-access charge;
- emits logs from the token's address, interleaved with the caller's logs in execution order.

When a TIP-20 entrypoint calls another precompile natively (TIP403Registry, AddressRegistry, AccountKeychain, ReceivePolicyGuard, StorageCredits) the same rules apply in reverse.

## 2. Addresses and constants

### 2.1 TIP-20 address space

```
TIP20_PREFIX = 0x20C000000000000000000000          # 12 bytes
tip20_address(id: uint64) = TIP20_PREFIX || be_bytes8(id)
is_tip20_prefix(a) = a[0:12] == TIP20_PREFIX
tip20_id(a) = be_uint64(a[12:20])   if is_tip20_prefix(a)
```

Every address with the prefix routes to the TIP-20 precompile, whether or not a token was created there ([00-framework.md](00-framework.md)). Token ids `0..1023` are **reserved**: the factory cannot create them (§10); they exist only if placed in the genesis allocation.

> **Resolved conflict C-T20-01**: the TIP-20 docs' factory section writes TIP20_PREFIX as a 13-byte value. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-t20-01).

| Constant | Value |
|---|---|
| `PATH_USD_ADDRESS` | `0x20C0000000000000000000000000000000000000` (token id 0) |
| `TIP20_FACTORY_ADDRESS` | `0x20FC000000000000000000000000000000000000` |
| `TIP20_CHANNEL_RESERVE_ADDRESS` | `0x4D50500000000000000000000000000000000000` (system precompile from T5) |
| `TIP_FEE_MANAGER_ADDRESS` | `0xfeEC000000000000000000000000000000000000` |
| `STABLECOIN_DEX_ADDRESS` | `0xDEc0000000000000000000000000000000000000` |
| `RECEIVE_POLICY_GUARD_ADDRESS` | `0xB10C000000000000000000000000000000000000` (system precompile from T6) |
| `ADDRESS_REGISTRY_ADDRESS` | `0xFDC0000000000000000000000000000000000000` (system precompile from T3) |
| `ZONE_PORTAL_PREFIX` | `0x5AD000000000000000000000` (12 bytes) |
| `DECIMALS` | `6` |
| `USD_CURRENCY` | the 3-byte string `"USD"` (compared byte-exact, case-sensitive) |
| `U128_MAX` | `2^128 - 1` |
| `ALLOW_ALL_POLICY_ID` | `1` (TIP-403 built-in; [tip403.md](tip403.md)) |
| `RESERVED_SIZE` | `1024` |

### 2.2 Roles

| Role | Value |
|---|---|
| `DEFAULT_ADMIN_ROLE` | `0x0000000000000000000000000000000000000000000000000000000000000000` |
| `UNGRANTABLE_ROLE` | `0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff` |
| `PAUSE_ROLE` = keccak256("PAUSE_ROLE") | `0x139c2898040ef16910dc9f44dc697df79363da767d8bc92f2e310312b816e46d` |
| `UNPAUSE_ROLE` = keccak256("UNPAUSE_ROLE") | `0x265b220c5a8891efdd9e1b1b7fa72f257bd5169f8d87e319cf3dad6ff52b94ae` |
| `ISSUER_ROLE` = keccak256("ISSUER_ROLE") | `0x114e74f6ea3bd819998f78687bfcb11b140da08e9b7d222fa9c1f1ba1f2aa122` |
| `BURN_BLOCKED_ROLE` = keccak256("BURN_BLOCKED_ROLE") | `0x7408fdc0d31c7bcb349eab611f5d1168acd4303574993f8cdc98b1cd18c41cae` |
| `BURN_AT_ROLE` = keccak256("BURN_AT_ROLE") | `0x39f6ee57cf2acaf8eab1056c2dcc3068f1f3d6a61e4777cf2bfdad7b1df90a27` |

### 2.3 Protected burn sources

`burnBlocked` and `burnAt` refuse to burn from the following sources (`ProtectedAddress`):

```python
def is_protected_burn_source(token, a) -> bool:
    if a in (TIP_FEE_MANAGER_ADDRESS, STABLECOIN_DEX_ADDRESS):        return True   # Genesis
    if is_active(T5) and a == TIP20_CHANNEL_RESERVE_ADDRESS:          return True
    if is_active(T6) and a == RECEIVE_POLICY_GUARD_ADDRESS:           return True
    if is_active(T5) and a == token:                                  return True   # the token's own address
    if is_active(T12) and a[0:12] == ZONE_PORTAL_PREFIX:              return True
    return False
```

### 2.4 Virtual addresses (TIP-1022)

A **virtual address** is any 20-byte address `a` with `a[4:14] == 0xFD × 10`; `masterId = a[0:4]`, `userTag = a[14:20]`. The AddressRegistry ([tip403.md](tip403.md)) maps a `masterId` to a master address. TIP-20 uses one registry procedure:

```python
def resolve_recipient(a) -> address:            # AddressRegistry, native
    if not is_active(T3): return a              # no storage access
    if a is not virtual: return a               # no storage access
    master = registry_master_of(a[0:4])         # one SLOAD on the registry (tip403.md)
    if master is None: fail(VirtualAddressUnregistered())   # 0xda56842c, AddressRegistry ABI
    return master
```

Before T3 a virtual address is an ordinary address for TIP-20 (it can receive and hold balance). From T3, TIP-20 never credits a virtual address on the paths that resolve recipients (§6.10, §6.11). Paths that do not resolve (`approve`, `permit`, the `from` side of any transfer, `burn*`) treat virtual addresses as ordinary addresses.

## 3. Precompile entry

### 3.1 Dispatch

A call whose target has the TIP-20 prefix is handled as follows. Steps 1 and 3 (input cost, decoding, unknown or not-yet-active selectors, static and delegate-call rules) are the common rules of [00-framework.md](00-framework.md).

```python
def tip20_call(token, calldata, msg_sender):
    charge_input_cost(calldata)                         # 1. framework
    # 2. initialization check
    try:
        initialized = ACCOUNT_READ(token).code_hash != KECCAK_EMPTY
    except Error as e:
        if not is_active(T4): initialized = False       # before T4 any failure (incl. out-of-gas) is masked
        else: raise e                                    # from T4 it propagates (out-of-gas halts)
    if not initialized: fail(Uninitialized())
    dispatch(calldata, msg_sender)                       # 3. framework; selector table §4.1
```

The initialization check runs for **every** selector, including `decimals()` and the role-constant views.

### 3.2 Uninitialized tokens

A prefixed address whose code is empty is an uninitialized token. An external call to it charges the input cost and the `ACCOUNT_READ`, then reverts `Uninitialized()` without decoding the calldata.

Internal callers (§1.3, §9) do not perform the initialization check. On an uninitialized token they read all-zero storage: `paused = false`, every balance 0, `currency = ""`, and a policy id of 0 (before T9 from slot 7; from T9 there is no binding, so the legacy slot is read), which the TIP-403 built-in policy 0 rejects for every account. The procedures then proceed or fail exactly as specified for that state (for example `system_transfer_from` reverts `PolicyForbids()`).

`TIP20Factory.isTIP20(a)` is `is_tip20_prefix(a) and ACCOUNT_READ(a).code_hash != KECCAK_EMPTY` (§10.3).

## 4. ABI

All TIP-20 entrypoints are standard Solidity ABI. String arguments are decoded as UTF-8 with lossy replacement (each invalid sequence becomes U+FFFD); when the framework's decoder validates (from T11, [00-framework.md](00-framework.md)), a `string` argument that is not valid UTF-8 fails decoding. Every length or content check in this chapter applies to the decoded string.

### 4.1 Functions

| Function | Selector | Kind | Dispatched from | Notes |
|---|---|---|---|---|
| `name()` | `0x06fdde03` | view | Genesis | string, slot 2 |
| `symbol()` | `0x95d89b41` | view | Genesis | string, slot 3 |
| `decimals()` | `0x313ce567` | view | Genesis | always 6 |
| `currency()` | `0xe5a6b10f` | view | Genesis | string, slot 4 |
| `totalSupply()` | `0x18160ddd` | view | Genesis | slot 8 |
| `supplyCap()` | `0x8f770ad0` | view | Genesis | slot 13 |
| `transferPolicyId()` | `0x9c4bad29` | view | Genesis | see §5.1 |
| `paused()` | `0x5c975abb` | view | Genesis | slot 12 |
| `logoURI()` | `0x6bb38b28` | view | T5 | string, slot 5 |
| `balanceOf(address)` | `0x70a08231` | view | Genesis | slot 9 |
| `allowance(address,address)` | `0xdd62ed3e` | view | Genesis | slot 10 |
| `quoteToken()` | `0x217a4b70` | view | Genesis | slot 6 |
| `nextQuoteToken()` | `0x7d0819b7` | view | Genesis | slot 7 bytes 0..19 |
| `PAUSE_ROLE()` | `0x389ed267` | view | Genesis | constant |
| `UNPAUSE_ROLE()` | `0x309756fb` | view | Genesis | constant |
| `ISSUER_ROLE()` | `0x82aefa24` | view | Genesis | constant |
| `BURN_BLOCKED_ROLE()` | `0x32ad9be8` | view | Genesis | constant |
| `BURN_AT_ROLE()` | `0xc6990381` | view | T12 | constant |
| `transferFrom(address,address,uint256)` | `0x23b872dd` | mutate | Genesis | returns bool |
| `transfer(address,uint256)` | `0xa9059cbb` | mutate | Genesis | returns bool |
| `approve(address,uint256)` | `0x095ea7b3` | mutate | Genesis | returns bool |
| `changeTransferPolicyId(uint64)` | `0xfd5e9420` | mutate | Genesis |  |
| `setSupplyCap(uint256)` | `0xb6a3f59a` | mutate | Genesis |  |
| `setLogoURI(string)` | `0xc30ff6df` | mutate | T5 |  |
| `pause()` | `0x8456cb59` | mutate | Genesis |  |
| `unpause()` | `0x3f4ba83a` | mutate | Genesis |  |
| `setNextQuoteToken(address)` | `0x4593223f` | mutate | Genesis |  |
| `completeQuoteTokenUpdate()` | `0x638bc4a3` | mutate | Genesis |  |
| `mint(address,uint256)` | `0x40c10f19` | mutate | Genesis |  |
| `mintWithMemo(address,uint256,bytes32)` | `0xe44f0b12` | mutate | Genesis |  |
| `burn(uint256)` | `0x42966c68` | mutate | Genesis |  |
| `burnWithMemo(uint256,bytes32)` | `0x38f23b0b` | mutate | Genesis |  |
| `burnBlocked(address,uint256)` | `0xec0cf3dc` | mutate | Genesis |  |
| `burnAt(address,uint256)` | `0x9803f216` | mutate | T12 |  |
| `transferWithMemo(address,uint256,bytes32)` | `0x95777d59` | mutate | Genesis | returns nothing |
| `transferFromWithMemo(address,address,uint256,bytes32)` | `0x929c2539` | mutate | Genesis | returns bool |
| `distributeReward(uint256)` | `0x940a4e45` | mutate | Genesis | no-op from T7 |
| `setRewardRecipient(address)` | `0xe521136f` | mutate | Genesis | no-op from T7 |
| `claimRewards()` | `0x372500ab` | mutate | Genesis | returns uint256 |
| `globalRewardPerToken()` | `0x726ce324` | view | Genesis | slot 15 |
| `optedInSupply()` | `0x8ef39dce` | view | Genesis | returns uint128, slot 16 |
| `userRewardInfo(address)` | `0x360b8ed9` | view | Genesis | returns (address,uint256,uint256) |
| `getPendingRewards(address)` | `0xf6ed2017` | view | Genesis | returns uint128 |
| `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | `0xd505accf` | mutate | T2 |  |
| `nonces(address)` | `0x7ecebe00` | view | T2 | slot 11 |
| `DOMAIN_SEPARATOR()` | `0x3644e515` | view | T2 | computed |
| `hasRole(address,bytes32)` | `0xac4ab3fb` | view | Genesis | IRolesAuth |
| `getRoleAdmin(bytes32)` | `0x248a9ca3` | view | Genesis | IRolesAuth |
| `grantRole(bytes32,address)` | `0x2f2ff15d` | mutate | Genesis | IRolesAuth |
| `revokeRole(bytes32,address)` | `0xd547741f` | mutate | Genesis | IRolesAuth |
| `renounceRole(bytes32)` | `0x8bb9c5bf` | mutate | Genesis | IRolesAuth |
| `setRoleAdmin(bytes32,bytes32)` | `0x1e4e0091` | mutate | Genesis | IRolesAuth |

A selector listed with a fork is unknown before that fork (`UnknownFunctionSelector(bytes4)`, [00-framework.md](00-framework.md)). "view" selectors may run in a static context; "mutate" selectors are rejected in a static context per [00-framework.md](00-framework.md). `userRewardInfo` returns the tuple `(address rewardRecipient, uint256 rewardPerToken, uint256 rewardBalance)`.

### 4.2 Events

All events are emitted by the token address, with standard Solidity log encoding.

| Event | topic0 | Indexed (topics 1..3, in order) | Data |
|---|---|---|---|
| `Transfer(address,address,uint256)` | `0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef` | from, to | amount |
| `Approval(address,address,uint256)` | `0x8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925` | owner, spender | amount |
| `Mint(address,uint256)` | `0x0f6798a560793a54c3bcfe86a93cde1e73087d944c0ea20544137d4121396885` | to | amount |
| `Burn(address,uint256)` | `0xcc16f5dbb4873280815c1ee09dbd06736cffcc184412cf7a71a0fdb75d397ca5` | from | amount |
| `BurnBlocked(address,uint256)` | `0xeff07194896bfa6254e521809f217f70dbdd9cefa6b894f5326af3ce8402c320` | from | amount |
| `BurnAt(address,address,uint256)` | `0x9272a54543b703f7620d2c151ff14b830f777d251b5f56678d191a9009ee9f35` | burner, from, amount | (none) |
| `TransferWithMemo(address,address,uint256,bytes32)` | `0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0` | from, to, memo | amount |
| `TransferPolicyUpdate(address,uint64)` | `0xa870ab07b4f8e8e92e8876245ea0ec666bc09ccf6814a1fb6a8e6984b1932cce` | updater, newPolicyId | (none) |
| `SupplyCapUpdate(address,uint256)` | `0x6d7e6630766134be7e051b11b8882e6f47926ddd2fd1268bebd168c30f055c4f` | updater, newSupplyCap | (none) |
| `PauseStateUpdate(address,bool)` | `0xf79595a776ff71356be9e7ff196226a16d0f4d637ff39031256c0eafd7af6b5e` | updater | isPaused |
| `NextQuoteTokenSet(address,address)` | `0x509c22f85ddeb1f3a347c45d225acd96afb87104e38b781e22a9376f0842a83a` | updater, nextQuoteToken | (none) |
| `QuoteTokenUpdate(address,address)` | `0xa2bc96949c0ac82a2c9b213d46c45d745e1e2567d1496b5e117d9c808ef004f3` | updater, newQuoteToken | (none) |
| `RewardDistributed(address,uint256)` | `0xe34918ff1c7084970068b53fd71ad6d8b04e9f15d3886cbf006443e6cdc52ea6` | funder | amount |
| `RewardRecipientSet(address,address)` | `0xbbf8c20751167a65b38d4dd87c3eba00bfae01d85fb809a89eee1ba842673b98` | holder, recipient | (none) |
| `LogoURIUpdated(address,string)` | `0x85e241dac85a215868931b91ac54f59cbac1b80f05dbc678b4376e4f2ce4c835` | updater | newLogoURI |
| `RoleMembershipUpdated(bytes32,address,address,bool)` | `0x4811f35680ba814bed6b0b926a2949c8a1000f4f2443cfe9978745d46a251aec` | role, account, sender | hasRole |
| `RoleAdminUpdated(bytes32,bytes32,address)` | `0x70d85637458e639f63e6106179309eadde21dacce320d9549168d49d0a9d6982` | role, newAdminRole, sender | (none) |

### 4.3 Errors

`ITIP20` errors:

| Error | Selector |
|---|---|
| `InsufficientBalance(uint256,uint256,address)` | `0x832f98b5` |
| `InsufficientAllowance()` | `0x13be252b` |
| `SupplyCapExceeded()` | `0xf58f733a` |
| `InvalidSupplyCap()` | `0xc0d76d92` |
| `InvalidPayload()` | `0x7c6953f9` |
| `PolicyForbids()` | `0x54cfe659` |
| `InvalidRecipient()` | `0x9c8d2cd2` |
| `ContractPaused()` | `0xab35696f` |
| `InvalidCurrency()` | `0xf5993428` |
| `InvalidQuoteToken()` | `0xd15b4fe2` |
| `InvalidAmount()` | `0x2c5211c6` |
| `NoOptedInSupply()` | `0xe845980e` |
| `Unauthorized()` | `0x82b42900` |
| `ProtectedAddress()` | `0xe1320079` |
| `InvalidToken()` | `0xc1ab6dc1` |
| `Uninitialized()` | `0x1c72fad4` |
| `InvalidTransferPolicyId()` | `0x7b94a16b` |
| `PermitExpired()` | `0x1a15a3cc` |
| `InvalidSignature()` | `0x8baa579f` |
| `LogoURITooLong()` | `0x8d2727af` |
| `InvalidLogoURI()` | `0xbc2579ba` |
| `RootKeyRetired(address)` | `0x5eb7b977` |
| `UnsupportedAddressVersion(uint8)` | `0x33d34e90` |
| `ZoneUnregistered(uint32)` | `0x93517f6c` |

`IRolesAuth` declares `Unauthorized()` with the same selector `0x82b42900`; role failures use it. `InvalidPayload`, `InvalidCurrency`, `UnsupportedAddressVersion` and `ZoneUnregistered` are declared but never raised by any mainnet path at T13 or earlier (`InvalidCurrency` is raised only by fee-token validation helpers, [fee-manager.md](fee-manager.md)). `RootKeyRetired` is raised only from T14.

Errors raised by native callees bubble up unchanged, including `VirtualAddressUnregistered()` (`0xda56842c`, AddressRegistry), `AddressReserved()` (`0x98387502`, ReceivePolicyGuard), the AccountKeychain spending-limit errors ([account-keychain.md](account-keychain.md)) and TIP-403 errors ([tip403.md](tip403.md)).

> **Resolved conflict C-T20-04**: the TIP-20 docs present an interface without the reward functions and events that the code dispatches at every fork. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-t20-04).

## 5. Storage layout

Token state lives in the token account's storage. Slots are assigned in declaration order with Solidity packing ([00-framework.md](00-framework.md)). The layout is identical to what solc assigns to the equivalent Solidity contract.

| Slot | Name | Type | Notes |
|---|---|---|---|
| 0 | `roles` | `mapping(address => mapping(bytes32 => bool))` | `roles[account][role]`: `keccak256(pad32(role) ‖ keccak256(pad32(account) ‖ pad32(0)))` |
| 1 | `roleAdmins` | `mapping(bytes32 => bytes32)` | unset reads as `DEFAULT_ADMIN_ROLE` |
| 2 | `name` | `string` | |
| 3 | `symbol` | `string` | |
| 4 | `currency` | `string` | |
| 5 | `logoURI` | `string` | dispatched from T5. Never written before T5 (previously an unused field), so it reads as `""` |
| 6 | `quoteToken` | `address` | bytes 0..19 (low-order) |
| 7 | `nextQuoteToken` | `address` | bytes 0..19 of slot 7 (bits 0..159) |
| 7 | `transferPolicyId` | `uint64` | bytes 20..27 of slot 7 (bits 160..223); legacy location, see §5.1 |
| 8 | `totalSupply` | `uint256` | |
| 9 | `balances` | `mapping(address => uint256)` | |
| 10 | `allowances` | `mapping(address => mapping(address => uint256))` | `allowances[owner][spender]` |
| 11 | `permitNonces` | `mapping(address => uint256)` | |
| 12 | `paused` | `bool` | |
| 13 | `supplyCap` | `uint256` | |
| 14 | (unused) | `mapping(bytes32 => bool)` | never read or written |
| 15 | `globalRewardPerToken` | `uint256` | |
| 16 | `optedInSupply` | `uint128` | low 16 bytes |
| 17 | `userRewardInfo` | `mapping(address => UserRewardInfo)` | 3 consecutive slots from `base = keccak256(pad32(account) ‖ pad32(17))` |

`UserRewardInfo` is `{ rewardRecipient: address @ base+0 (low 20 bytes), rewardPerToken: uint256 @ base+1, rewardBalance: uint256 @ base+2 }`. Reading it is `SLOAD(base)`, `SLOAD(base+1)`, `SLOAD(base+2)`. Writing it writes all three slots in order; before T4 the write of `base+0` is preceded by `SLOAD(base+0)` (read-modify-write of the packed group), from T4 it is not.

Writes to `quoteToken` (slot 6, alone in its slot) are plain `SSTORE`s. Writes to `nextQuoteToken` and to the legacy `transferPolicyId` are `RMW(7, …)` and preserve the other field's bytes. Example: pathUSD in the mainnet genesis has slot 7 = `0x0000000000000000000000010000000000000000000000000000000000000000` (policy 1, next quote token 0).

### 5.1 Effective transfer policy (T9 binding)

```python
def transfer_policy_id(token) -> uint64:
    if is_active(T9):
        bound = TIP403Registry.registered_token_transfer_policy_id(token)   # native; its SLOAD is in tip403.md
        if bound is not None: return bound
    return SLOAD(token, 7).bytes[20:28]           # legacy slot
```

From T9, `changeTransferPolicyId` and token creation write the binding in the TIP403Registry (`set_token_transfer_policy`, [tip403.md](tip403.md)) and do not write slot 7. A token created before T9 keeps its legacy slot-7 value until the binding is set (by `changeTransferPolicyId` or by the registry's migration, which also clears the legacy field). For such a token every policy read from T9 costs the registry read plus `SLOAD(7)`.

## 6. Common procedures

All procedures run against one token `T` (its address is `T.address`). Each listed operation is metered as in §1.2.

### 6.1 Roles check

```python
def check_role(account, role):
    if SLOAD(roles[account][role]) == 0: fail(Unauthorized())     # 0x82b42900
```

### 6.2 Pause check

```python
def check_not_paused():
    if SLOAD(12) != 0: fail(ContractPaused())
```

### 6.3 Recipient resolution and validity

```python
class Recipient:            # target: address credited; virtual: original virtual address or None
    def original(self): return self.virtual if self.virtual is not None else self.target

def resolve(a) -> Recipient:
    m = resolve_recipient(a)                          # §2.4
    return Recipient(target=a, virtual=None) if m == a else Recipient(target=m, virtual=a)

def direct(a) -> Recipient: return Recipient(target=a, virtual=None)

def validate(r: Recipient):                           # pure, no gas
    if r.target == 0 or is_tip20_prefix(r.target): fail(InvalidRecipient())

def transfer_event(r, frm, amount):  return Transfer(frm, r.original(), amount)
def hop_event(r, amount):            return Transfer(r.virtual, r.target, amount) if r.virtual else None
```

### 6.4 TIP-403 authorization

```python
def is_transfer_authorized(frm, to) -> bool:
    pid = transfer_policy_id(T)                                         # §5.1
    s = TIP403Registry.is_authorized_as(pid, frm, SENDER)
    if is_active(T2) and not s: return False                            # T2: recipient lookup skipped
    r = TIP403Registry.is_authorized_as(pid, to, RECIPIENT)
    return s and r

def ensure_transfer_authorized(frm, to):
    if not is_transfer_authorized(frm, to): fail(PolicyForbids())

def ensure_authorized_as(pairs):          # list of (user, role), checked in order
    pid = transfer_policy_id(T)
    for (user, role) in pairs:
        if not TIP403Registry.is_authorized_as(pid, user, role): fail(PolicyForbids())
```

Before T2, both lookups always run. The role semantics (including the T2 compound-policy directional roles) and their storage reads are in [tip403.md](tip403.md).

### 6.5 Spending limit and allowance

```python
def check_and_update_spending_limit(frm, amount):
    AccountKeychain.authorize_transfer(frm, T.address, amount)          # account-keychain.md

def consume_allowance(owner, spender, amount):
    allowed = SLOAD(allowances[owner][spender])
    if amount > allowed: fail(InsufficientAllowance())
    if allowed != 2**256 - 1:
        SSTORE(allowances[owner][spender], allowed - amount)            # infinite allowance is never decremented
```

### 6.6 Balance updates

```python
def increment_balance(a, amount):
    SINC(balances[a], amount)          # on overflow: fail(SupplyCapExceeded())

def decrement_balance(a, amount):
    SDEC(balances[a], amount)          # on underflow with current value c: fail(InsufficientBalance(c, amount, T.address))
```

### 6.7 Core transfer

```python
def _transfer(frm, to: Recipient, amount):
    if not is_active(T8):
        b = SLOAD(balances[frm])
        if amount > b: fail(InsufficientBalance(b, amount, T.address))
    handle_rewards_on_transfer(frm, to.target, amount)                  # §8.3; no operations from T8
    if not is_active(T8):
        SSTORE(balances[frm], b - amount)
    else:
        decrement_balance(frm, amount)
    if to.target != 0:
        increment_balance(to.target, amount)
    LOG(transfer_event(to, frm, amount))
```

A transfer to `direct(0)` (used by burns) debits `frm` and credits nobody. A self-transfer is permitted and follows the same sequence.

### 6.8 Mint core

```python
def _mint(to: Recipient, total_supply, amount):       # total_supply was read by the caller
    new_supply = total_supply + amount                # overflow: fail(Panic(0x11))
    if new_supply > SLOAD(13): fail(SupplyCapExceeded())
    handle_rewards_on_mint(to.target, amount)         # §8.3; no operations from T8
    SSTORE(8, new_supply)
    increment_balance(to.target, amount)
    LOG(transfer_event(to, 0, amount))
```

### 6.9 Receive policy (T6)

```python
def validate_inbound_or_block(originator, to: Recipient, amount, mint_total_supply, memo) -> bool:
    if not is_active(T6): return False
    if to.target == RECEIVE_POLICY_GUARD_ADDRESS: fail(AddressReserved())      # ReceivePolicyGuard error 0x98387502
    blocked = TIP403Registry.check_receive_policy(T.address, originator, to.target)   # tip403.md
    if blocked is None: return False
    (reason, recovery) = blocked
    # (zone-only "revert blocked inbound" mode is never enabled on Tempo mainnet)
    guard = direct(RECEIVE_POLICY_GUARD_ADDRESS)
    if mint_total_supply is not None:
        _mint(guard, mint_total_supply, amount)                         # Transfer(0, guard, amount)
        LOG(Mint(RECEIVE_POLICY_GUARD_ADDRESS, amount))
        kind = MINT
    else:
        _transfer(originator, guard, amount)                            # Transfer(originator, guard, amount)
        kind = TRANSFER
    ReceivePolicyGuard.store_blocked(T.address, originator, to, recovery, amount, reason, kind, memo)   # tip403.md
    return True
```

When it returns `True` the caller returns success immediately: the recipient is not credited, and no `TransferWithMemo`, `Mint(to, …)` or virtual hop event is emitted by the token for that operation. `store_blocked` receives the full `Recipient` (original virtual address preserved) and emits the guard's own event after the token's events.

### 6.10 Transfer validation

```python
def validate_transfer(spender, frm, to_addr, amount, memo) -> Recipient | None:
    to = resolve(to_addr)                         # 1  (T3+: may fail VirtualAddressUnregistered)
    check_not_paused()                            # 2
    validate(to)                                  # 3  InvalidRecipient
    ensure_transfer_authorized(frm, to.target)    # 4  PolicyForbids
    if spender is not None:
        consume_allowance(frm, spender, amount)   # 5a InsufficientAllowance
    else:
        check_and_update_spending_limit(frm, amount)   # 5b
    if validate_inbound_or_block(frm, to, amount, None, memo):   # 6 (T6+)
        return None
    return to
```

### 6.11 Mint validation

```python
def validate_mint(msg_sender, to_addr, amount, memo, recipient_role) -> (total_supply, Recipient) | None:
    to = resolve(to_addr)                         # 1
    check_role(msg_sender, ISSUER_ROLE)           # 2
    total_supply = SLOAD(8)                       # 3
    if is_active(T3):
        check_not_paused()                        # 4
        validate(to)                              # 5  (before T3 a mint may credit 0 or a prefixed address)
    pid = transfer_policy_id(T)
    if not TIP403Registry.is_authorized_as(pid, to.target, recipient_role): fail(PolicyForbids())   # 6
    if validate_inbound_or_block(msg_sender, to, amount, total_supply, memo):   # 7 (T6+)
        return None
    return (total_supply, to)
```

`recipient_role` is the TIP-403 `mintRecipient` role for the public mint entrypoints.

## 7. Entrypoints

Each entrypoint below starts after §3.1 (input cost, initialization check, decoding). `msg_sender` is the frame caller.

### 7.1 Views

| Function | Operations | Result |
|---|---|---|
| `name`, `symbol`, `currency`, `logoURI` | `STR_READ(2/3/4/5)` | string |
| `decimals` | none | `6` |
| `totalSupply`, `supplyCap`, `paused` | `SLOAD(8/13/12)` | |
| `quoteToken` | `SLOAD(6)` | |
| `nextQuoteToken` | `SLOAD(7)` | bytes 0..19 |
| `transferPolicyId` | §5.1 | |
| `balanceOf(a)` | `SLOAD(balances[a])` | |
| `allowance(o, s)` | `SLOAD(allowances[o][s])` | |
| `nonces(o)` (T2) | `SLOAD(permitNonces[o])` | |
| `DOMAIN_SEPARATOR` (T2) | §7.4 | |
| role constants | none | §2.2 |
| `hasRole(a, r)` | `SLOAD(roles[a][r])` | |
| `getRoleAdmin(r)` | `SLOAD(roleAdmins[r])` | |
| `globalRewardPerToken` | `SLOAD(15)` | |
| `optedInSupply` | `SLOAD(16)` | uint128 |
| `userRewardInfo(a)` | 3 × `SLOAD` (§5) | |
| `getPendingRewards(a)` | §8.5 | uint128 |

### 7.2 transfer, transferWithMemo, transferFrom, transferFromWithMemo

```python
def transfer(msg_sender, to, amount) -> bool:
    r = validate_transfer(None, msg_sender, to, amount, ZERO32)
    if r is None: return True
    _transfer(msg_sender, r, amount)                                   # Transfer(sender, original_to)
    if hop_event(r, amount): LOG(hop_event(r, amount))                 # Transfer(virtual, master)
    return True

def transfer_with_memo(msg_sender, to, amount, memo):                  # returns nothing
    r = validate_transfer(None, msg_sender, to, amount, memo)
    if r is None: return
    _transfer(msg_sender, r, amount)
    LOG(TransferWithMemo(msg_sender, to, amount, memo))                # 'to' as passed (virtual if virtual)
    if hop_event(r, amount): LOG(hop_event(r, amount))

def transfer_from(msg_sender, frm, to, amount) -> bool:
    r = validate_transfer(msg_sender, frm, to, amount, ZERO32)
    if r is None: return True
    _transfer(frm, r, amount)
    if hop_event(r, amount): LOG(hop_event(r, amount))
    return True

def transfer_from_with_memo(msg_sender, frm, to, amount, memo) -> bool:
    r = validate_transfer(msg_sender, frm, to, amount, memo)
    if r is None: return True
    _transfer(frm, r, amount)
    LOG(TransferWithMemo(frm, to, amount, memo))
    if hop_event(r, amount): LOG(hop_event(r, amount))
    return True
```

The direct variants charge the access-key spending limit of `msg_sender` and never touch allowances. The `From` variants consume the allowance and never touch spending limits. A zero amount is permitted and runs every step.

### 7.3 approve

```python
def approve(msg_sender, spender, amount) -> bool:
    old = SLOAD(allowances[msg_sender][spender])
    AccountKeychain.authorize_approve(msg_sender, T.address, old, amount)   # account-keychain.md
    SSTORE(allowances[msg_sender][spender], amount)
    LOG(Approval(msg_sender, spender, amount))
    return True
```

`approve` is allowed while paused, performs no TIP-403 check and does not resolve virtual addresses.

### 7.4 permit (from T2) and DOMAIN_SEPARATOR

```python
PERMIT_TYPEHASH       = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
                      = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9
EIP712_DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                      = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f
VERSION_HASH          = keccak256("1") = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6

def domain_separator() -> bytes32:
    name = STR_READ(2)
    name_hash = KECCAK(len(name))
    return KECCAK(160)(abi.encode(EIP712_DOMAIN_TYPEHASH, name_hash, VERSION_HASH, uint256(chain_id), T.address))

def permit(owner, spender, value, deadline, v, r, s):
    if block.timestamp > deadline: fail(PermitExpired())               # 1
    nonce = SLOAD(permitNonces[owner])                                  # 2
    struct_hash = KECCAK(192)(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline))
    digest = KECCAK(66)(0x19 ‖ 0x01 ‖ domain_separator() ‖ struct_hash)  # domain_separator ops run before this KECCAK
    ECRECOVER                                                           # 3: 3,000 gas, always charged
    if v not in (27, 28): fail(InvalidSignature())
    signer = secp256k1_recover(digest, v, r, s)                         # EIP-2: s > secp256k1n/2 fails
    if signer is None or signer == 0 or signer != owner: fail(InvalidSignature())
    # (from T14 only: retired-root check; no operation before T14)
    if nonce == 2**256 - 1: fail(Panic(0x11))
    SSTORE(permitNonces[owner], nonce + 1)                              # 4
    SSTORE(allowances[owner][spender], value)                           # 5
    LOG(Approval(owner, spender, value))                                # 6
```

`permit` ignores `msg_sender`, is allowed while paused, performs no TIP-403 or spending-limit check, and accepts only `v ∈ {27, 28}` (no normalization of 0/1). `chain_id` is the chain's configured chain id. The domain separator is recomputed on every call from the stored name and the chain id.

> **Resolved conflict C-T20-06**: TIP-1004 orders the nonce increment before signature validation; the step order above (validation first) is what produced mainnet gas. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-t20-06).

### 7.5 mint and mintWithMemo

```python
def mint(msg_sender, to, amount):
    res = validate_mint(msg_sender, to, amount, ZERO32, MINT_RECIPIENT)
    if res is None: return
    (total_supply, r) = res
    _mint(r, total_supply, amount)                                     # Transfer(0, original_to)
    LOG(Mint(to, amount))                                              # 'to' as passed
    if hop_event(r, amount): LOG(hop_event(r, amount))

def mint_with_memo(msg_sender, to, amount, memo):
    res = validate_mint(msg_sender, to, amount, memo, MINT_RECIPIENT)
    if res is None: return
    (total_supply, r) = res
    _mint(r, total_supply, amount)                                     # Transfer(0, original_to)
    LOG(TransferWithMemo(0, to, amount, memo))
    LOG(Mint(to, amount))
    if hop_event(r, amount): LOG(hop_event(r, amount))
```

Minting does not consult access-key spending limits. Before T3 a paused token can be minted, and `to` may be the zero address or a prefixed address (credited like any other).

### 7.6 burn and burnWithMemo

```python
def _burn(msg_sender, amount):
    if is_active(T3): check_not_paused()
    check_role(msg_sender, ISSUER_ROLE)
    _transfer(msg_sender, direct(0), amount)                           # Transfer(sender, 0)
    ts = SLOAD(8)
    if amount > ts: fail(InsufficientBalance(ts, amount, T.address))
    SSTORE(8, ts - amount)

def burn(msg_sender, amount):
    _burn(msg_sender, amount)
    LOG(Burn(msg_sender, amount))

def burn_with_memo(msg_sender, amount, memo):
    _burn(msg_sender, amount)
    LOG(TransferWithMemo(msg_sender, 0, amount, memo))
    LOG(Burn(msg_sender, amount))
```

No TIP-403 check and no spending-limit check apply to `burn`.

### 7.7 burnBlocked

```python
def burn_blocked(msg_sender, owner, amount, check_protected=True):
    if is_active(T3): check_not_paused()                                # 1
    check_role(msg_sender, BURN_BLOCKED_ROLE)                           # 2
    if check_protected and is_protected_burn_source(T.address, owner):  # 3 (pure)
        fail(ProtectedAddress())
    pid = transfer_policy_id(T)                                         # 4
    if TIP403Registry.is_authorized_as(pid, owner, SENDER): fail(PolicyForbids())   # must be blocked
    burn_from = owner if check_protected else RECEIVE_POLICY_GUARD_ADDRESS
    _transfer(burn_from, direct(0), amount)                             # 5: Transfer(burn_from, 0)
    ts = SLOAD(8)
    if amount > ts: fail(InsufficientBalance(ts, amount, T.address))
    SSTORE(8, ts - amount)
    LOG(BurnBlocked(owner, amount))
```

The ABI entrypoint always uses `check_protected = True`. `check_protected = False` is used only by the ReceivePolicyGuard's receipt burn (from T6, [tip403.md](tip403.md) §4.7): the balance is taken from the guard, the policy check still applies to `owner`, and the role check applies to the account that called the guard.

### 7.8 burnAt (from T12)

```python
def burn_at(msg_sender, frm, amount):
    check_not_paused()                                                  # 1
    check_role(msg_sender, BURN_AT_ROLE)                                # 2
    if is_protected_burn_source(T.address, frm): fail(ProtectedAddress())   # 3
    check_and_update_spending_limit(frm, amount)                        # 4 (applies when frm is the tx origin)
    _transfer(frm, direct(0), amount)                                   # 5: Transfer(frm, 0)
    ts = SLOAD(8)
    if amount > ts: fail(InsufficientBalance(ts, amount, T.address))
    SSTORE(8, ts - amount)
    LOG(BurnAt(msg_sender, frm, amount))
```

No TIP-403 check applies.

### 7.9 changeTransferPolicyId

```python
def change_transfer_policy_id(msg_sender, new_id):
    check_role(msg_sender, DEFAULT_ADMIN_ROLE)
    if not TIP403Registry.policy_exists(new_id): fail(InvalidTransferPolicyId())   # tip403.md
    if is_active(T9): TIP403Registry.set_token_transfer_policy(T.address, new_id)  # tip403.md
    else:             RMW(7, transferPolicyId = new_id)
    LOG(TransferPolicyUpdate(msg_sender, new_id))
```

### 7.10 setSupplyCap

```python
def set_supply_cap(msg_sender, cap):
    check_role(msg_sender, DEFAULT_ADMIN_ROLE)
    if cap < SLOAD(8): fail(InvalidSupplyCap())
    if cap > U128_MAX: fail(SupplyCapExceeded())
    SSTORE(13, cap)
    LOG(SupplyCapUpdate(msg_sender, cap))
```

### 7.11 pause and unpause

```python
def pause(msg_sender):
    check_role(msg_sender, PAUSE_ROLE);   SSTORE(12, 1); LOG(PauseStateUpdate(msg_sender, True))
def unpause(msg_sender):
    check_role(msg_sender, UNPAUSE_ROLE); SSTORE(12, 0); LOG(PauseStateUpdate(msg_sender, False))
```

Both write and emit even when the state does not change.

While `paused` is set, these revert `ContractPaused()`: `transfer`, `transferFrom` and their memo variants, `system_transfer_from`, `transfer_fee_pre_tx`, `channel_reserve_transfer`, `release_blocked_funds`, `burnAt`, `claimRewards`, `distributeReward` and `setRewardRecipient` before T7, and from T3 `mint`, `mintWithMemo`, `burn`, `burnWithMemo` and `burnBlocked`. These are not affected: `approve`, `permit`, `transfer_fee_post_tx`, every admin and role function, every view, and from T7 the no-op `distributeReward` and `setRewardRecipient`.

### 7.12 setLogoURI (from T5)

```python
MAX_LOGO_URI_BYTES = 256
ALLOWED_LOGO_URI_SCHEMES = ("https", "http", "ipfs", "data")      # ASCII case-insensitive

def validate_logo_uri(uri):                       # pure
    if len(uri.bytes) > 256: fail(LogoURITooLong())
    if uri == "": return
    if ":" not in uri: fail(InvalidLogoURI())
    scheme = uri.split(":", 1)[0]                 # text before the first ':'
    if scheme == "" or not scheme[0].is_ascii_alpha(): fail(InvalidLogoURI())
    if any(not (c.is_ascii_alnum() or c in "+-.") for c in scheme[1:]): fail(InvalidLogoURI())
    if scheme.lower_ascii() not in ALLOWED_LOGO_URI_SCHEMES: fail(InvalidLogoURI())

def write_logo_uri(updater, uri):                 # no role check
    validate_logo_uri(uri)
    STR_WRITE(5, uri)
    LOG(LogoURIUpdated(updater, uri))

def set_logo_uri(msg_sender, uri):
    check_role(msg_sender, DEFAULT_ADMIN_ROLE)
    write_logo_uri(msg_sender, uri)
```

Nothing after the scheme is validated. The empty string clears the URI (and still emits the event).

### 7.13 setNextQuoteToken and completeQuoteTokenUpdate

```python
def set_next_quote_token(msg_sender, q):
    check_role(msg_sender, DEFAULT_ADMIN_ROLE)                       # 1
    if T.address == PATH_USD_ADDRESS: fail(InvalidQuoteToken())      # 2
    if not TIP20Factory.is_tip20(q): fail(InvalidQuoteToken())       # 3: prefix check, then ACCOUNT_READ(q)
    if STR_READ(4) == "USD":                                         # 4: own currency
        if STR_READ(q, 4) != "USD": fail(InvalidQuoteToken())        #    q's currency
    RMW(7, nextQuoteToken = q)                                       # 5
    LOG(NextQuoteTokenSet(msg_sender, q))

def complete_quote_token_update(msg_sender):
    check_role(msg_sender, DEFAULT_ADMIN_ROLE)
    nxt = SLOAD(7).nextQuoteToken
    cur = nxt
    while cur != PATH_USD_ADDRESS:
        if cur == T.address: fail(InvalidQuoteToken())               # cycle through this token
        if not is_tip20_prefix(cur): fail(InvalidToken())
        cur = SLOAD(cur, 6)                                          # quoteToken of cur (no ACCOUNT_READ)
    SSTORE(6, nxt)
    LOG(QuoteTokenUpdate(msg_sender, nxt))
```

Consequences: `q == T.address` is accepted by `setNextQuoteToken` and rejected at completion; completing with nothing newly staged rewrites the current value; on pathUSD (whose `nextQuoteToken` is 0) completion reverts `InvalidToken()`; a chain reaching a token whose quote token is 0 also reverts `InvalidToken()`. The loop has no explicit bound: it terminates because no cycle can be created, and each hop costs one `SLOAD`.

### 7.14 Roles (IRolesAuth)

```python
def grant_role(msg_sender, role, account):
    admin = SLOAD(roleAdmins[role]); check_role(msg_sender, admin)
    SSTORE(roles[account][role], 1)
    LOG(RoleMembershipUpdated(role, account, msg_sender, True))

def revoke_role(msg_sender, role, account):
    admin = SLOAD(roleAdmins[role]); check_role(msg_sender, admin)
    SSTORE(roles[account][role], 0)
    LOG(RoleMembershipUpdated(role, account, msg_sender, False))

def renounce_role(msg_sender, role):
    check_role(msg_sender, role)                   # Unauthorized unless the caller holds the role
    SSTORE(roles[msg_sender][role], 0)
    LOG(RoleMembershipUpdated(role, msg_sender, msg_sender, False))

def set_role_admin(msg_sender, role, admin_role):
    cur = SLOAD(roleAdmins[role]); check_role(msg_sender, cur)
    SSTORE(roleAdmins[role], admin_role)
    LOG(RoleAdminUpdated(role, admin_role, msg_sender))
```

Writes and events are unconditional (granting a held role or revoking an absent one still writes and emits). Every role's admin defaults to `DEFAULT_ADMIN_ROLE`. `UNGRANTABLE_ROLE` is its own admin (set at creation), so nobody can grant it or change its admin.

### 7.15 Event order summary

For allowed (not diverted) operations, logs from the token in emission order:

| Operation | Logs |
|---|---|
| `transfer`, `transferFrom` | `Transfer(from, to)` [, `Transfer(to, master)` if `to` is virtual] |
| `transferWithMemo`, `transferFromWithMemo` | `Transfer(from, to)`, `TransferWithMemo(from, to, memo)` [, `Transfer(to, master)`] |
| `mint` | `Transfer(0, to)`, `Mint(to)` [, `Transfer(to, master)`] |
| `mintWithMemo` | `Transfer(0, to)`, `TransferWithMemo(0, to, memo)`, `Mint(to)` [, `Transfer(to, master)`] |
| `burn` | `Transfer(from, 0)`, `Burn(from)` |
| `burnWithMemo` | `Transfer(from, 0)`, `TransferWithMemo(from, 0, memo)`, `Burn(from)` |
| `burnBlocked` | `Transfer(owner, 0)`, `BurnBlocked(owner)` (guard receipt burn: `Transfer(guard, 0)`, `BurnBlocked(owner)`) |
| `burnAt` | `Transfer(from, 0)`, `BurnAt(burner, from, amount)` |
| transfer diverted by receive policy (T6+) | `Transfer(from, guard)`, then the guard's `TransferBlocked` |
| mint diverted by receive policy (T6+) | `Transfer(0, guard)`, `Mint(guard)`, then the guard's `TransferBlocked` |

Here `to` is the address passed by the caller (the virtual address when virtual) and `master` its resolved master.

## 8. Rewards (Genesis to T8)

TIP-20 tokens carry an opt-in reward system. Holders opt in by naming a reward recipient; anyone can distribute tokens pro rata over the opted-in supply. It was deprecated in two steps (TIP-1075): from T7 `distributeReward` and `setRewardRecipient` are successful no-ops; from T8 balance-changing paths stop updating reward state. `claimRewards` remains at every fork. Replaying blocks before T8 requires this section exactly.

```
ACC_PRECISION = 10**18
```

### 8.1 update_rewards

```python
def update_rewards(holder) -> address:            # returns holder's reward recipient ("delegate")
    if is_active(T8): return 0                    # no operations
    info = read UserRewardInfo[holder]            # 3 x SLOAD
    delegate = info.rewardRecipient
    g = SLOAD(15)
    delta = g - info.rewardPerToken               # underflow: fail(Panic(0x11))
    if delta != 0:
        if delegate != 0:
            bal = SLOAD(balances[holder])
            reward = (bal * delta) // ACC_PRECISION        # multiplication overflow: fail(Panic(0x11))
            if delegate == holder:
                info.rewardBalance += reward               # overflow: fail(Panic(0x11))
            else:
                d = read UserRewardInfo[delegate]          # 3 x SLOAD
                d.rewardBalance += reward                  # overflow: fail(Panic(0x11))
                write UserRewardInfo[delegate] = d         # §5 struct write
        info.rewardPerToken = g
        write UserRewardInfo[holder] = info                # §5 struct write
    return delegate
```

`optedInSupply` adjustments below compute in 256 bits and then require the result to fit in `uint128`; underflow or a result above `2^128 - 1` fails `Panic(0x11)`. Each adjustment is `SLOAD(16)` then `SSTORE(16, new)`.

### 8.2 distributeReward

```python
def distribute_reward(msg_sender, amount):
    if is_active(T7): return                                   # no-op, even when paused
    check_not_paused()
    if amount == 0: fail(InvalidAmount())
    ensure_transfer_authorized(msg_sender, T.address)
    check_and_update_spending_limit(msg_sender, amount)
    _transfer(msg_sender, direct(T.address), amount)           # Transfer(sender, token)
    opted_in = SLOAD(16)
    if opted_in == 0: fail(NoOptedInSupply())
    delta_rpt = (amount * ACC_PRECISION) // opted_in                # overflow: fail(Panic(0x11))
    g = SLOAD(15)
    SSTORE(15, g + delta_rpt)                                  # overflow: fail(Panic(0x11))
    LOG(RewardDistributed(msg_sender, amount))
```

The distributed tokens are held in the token's own balance (`balances[T.address]`). Note that `_transfer` to `T.address` runs `handle_rewards_on_transfer(sender, T.address, amount)` before `optedInSupply` is read.

### 8.3 Reward hooks on balance changes

```python
def handle_rewards_on_transfer(frm, to, amount):           # called by _transfer
    fd = update_rewards(frm)
    td = update_rewards(to)
    if fd != 0 and td == 0:   opted_in_supply -= amount
    elif fd == 0 and td != 0: opted_in_supply += amount

def handle_rewards_on_mint(to, amount):                    # called by _mint
    td = update_rewards(to)
    if td != 0: opted_in_supply += amount
```

From T8 `update_rewards` returns 0 without operations, so both hooks do nothing. Burns go through `_transfer` with `to = 0`, so before T8 they call `update_rewards(0)`. The fee hooks (§9.2) adjust rewards for the payer only.

### 8.4 setRewardRecipient

```python
def set_reward_recipient(msg_sender, recipient):
    if is_active(T7): return                                   # no-op, even when paused
    check_not_paused()
    if is_active(T3) and recipient is virtual: fail(InvalidRecipient())
    if recipient != 0: ensure_transfer_authorized(msg_sender, recipient)
    fd = update_rewards(msg_sender)
    bal = SLOAD(balances[msg_sender])
    if fd != 0:
        if recipient == 0: opted_in_supply -= bal
    elif recipient != 0:
        opted_in_supply += bal
    info = read UserRewardInfo[msg_sender]                     # 3 x SLOAD (re-read)
    info.rewardRecipient = recipient
    write UserRewardInfo[msg_sender] = info                    # struct write
    LOG(RewardRecipientSet(msg_sender, recipient))
```

### 8.5 claimRewards and getPendingRewards

```python
def claim_rewards(msg_sender) -> uint256:
    check_not_paused()
    ensure_transfer_authorized(T.address, msg_sender)
    rr = update_rewards(msg_sender)                            # 0 from T8
    info = read UserRewardInfo[msg_sender]                     # 3 x SLOAD
    cb = SLOAD(balances[T.address])
    pay = min(info.rewardBalance, cb)
    info.rewardBalance -= pay
    write UserRewardInfo[msg_sender] = info                    # always written
    if pay > 0:
        SSTORE(balances[T.address], cb - pay)
        b = SLOAD(balances[msg_sender])
        SSTORE(balances[msg_sender], b + pay)                  # overflow: fail(Panic(0x11))
        if rr != 0: opted_in_supply += pay
        LOG(Transfer(T.address, msg_sender, pay))
    return pay

def get_pending_rewards(account) -> uint128:                   # view
    info = read UserRewardInfo[account]                        # 3 x SLOAD
    pending = info.rewardBalance
    if not is_active(T8) and info.rewardRecipient == account:
        bal = SLOAD(balances[account])
        if bal > 0:
            g = SLOAD(15)
            delta = g - info.rewardPerToken                    # underflow: fail(Panic(0x11))
            if delta > 0: pending += (bal * delta) // ACC_PRECISION
    if pending >= 2**128: fail(Panic(0x11))
    return pending
```

`claimRewards` credits the caller directly (no virtual resolution, no receive policy, no spending limit). From T8 only already-settled `rewardBalance` is paid; accrual not yet checkpointed by T8 is never paid.

## 9. Internal hooks (not in the ABI)

These procedures are invoked natively (§1.3). They are not reachable by any selector.

### 9.1 system_transfer_from

Moves tokens from `frm` to the calling precompile without an allowance. The recipient is always the caller.

```python
def system_transfer_from(caller, frm, amount) -> bool:
    if is_active(T5) and caller not in (TIP_FEE_MANAGER_ADDRESS, STABLECOIN_DEX_ADDRESS,
                                         TIP20_CHANNEL_RESERVE_ADDRESS):    # TIP-1035 Implicit Approval List
        fail(Unauthorized())
    r = validate_transfer(None, frm, caller, amount, ZERO32)    # full §6.10, incl. T6 receive policy of the caller
    if r is None: return True
    _transfer(frm, r, amount)                                    # Transfer(frm, caller)
    if hop_event(r, amount): LOG(hop_event(r, amount))
    return True
```

Before T5 the caller is not checked (the fee manager was its only caller). Callers pull only from their own `msg.sender`; this is the callers' obligation, not checked here.

> **Resolved conflict C-T20-05**: the TIP-20 docs and TIP-1035 describe `system_transfer_from(from, to, amount)`; the hook takes no recipient and always credits the calling precompile. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-t20-05).

### 9.2 Fee hooks

Called by the fee manager around transaction execution ([fee-manager.md](fee-manager.md) defines when, in which gas context, and with which amounts).

```python
def transfer_fee_pre_tx(frm, amount):
    check_not_paused()
    check_and_update_spending_limit(frm, amount)
    rr = update_rewards(frm)                                      # 0 from T8
    if rr != 0: opted_in_supply -= amount
    decrement_balance(frm, amount)                                # InsufficientBalance(c, amount, token)
    increment_balance(TIP_FEE_MANAGER_ADDRESS, amount)
    # no event

def transfer_fee_post_tx(to, refund, actual_spending):
    LOG(Transfer(to, TIP_FEE_MANAGER_ADDRESS, actual_spending))   # always, even if actual_spending == 0, even when paused
    if refund == 0: return
    if is_active(T1C): AccountKeychain.refund_spending_limit(to, T.address, refund)
    rr = update_rewards(to)                                       # 0 from T8
    if rr != 0: opted_in_supply += refund
    decrement_balance(TIP_FEE_MANAGER_ADDRESS, refund)
    increment_balance(to, refund)
```

Neither hook checks TIP-403, resolves virtual addresses, applies receive policies, or changes `totalSupply`. `transfer_fee_post_tx` does not check the pause flag.

> **Resolved conflict C-FORKS-04**: TIP-1036 attributes the spending-limit refund in `transfer_fee_post_tx` to T2; it is active from T1C. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-forks-04).

### 9.3 channel_reserve_transfer (from T12)

Custody movement for the channel reserve (§11.8). Not reachable before T12.

```python
def channel_reserve_transfer(frm, to: Recipient, amount, receive_policy_sender):
    if frm != TIP20_CHANNEL_RESERVE_ADDRESS and to.original() != TIP20_CHANNEL_RESERVE_ADDRESS:
        fail(Unauthorized())
    check_not_paused()
    validate(to)                                                  # InvalidRecipient
    check_and_update_spending_limit(frm, amount)
    if to.target == RECEIVE_POLICY_GUARD_ADDRESS: fail(AddressReserved())
    if TIP403Registry.validate_receive_policy(T.address, receive_policy_sender, to.target) is not None:
        fail(PolicyForbids())                                     # reverts; never diverts to the guard
    _transfer(frm, to, amount)
    if hop_event(to, amount): LOG(hop_event(to, amount))
```

No TIP-403 sender/recipient check runs here; the reserve performs the logical checks itself (§11).

### 9.4 release_blocked_funds (from T6)

Called by the ReceivePolicyGuard when a receipt is claimed. The normative definition, including `RecoveryMode`, `is_reroute`, `policy_subject` and `spending_account`, is [tip403.md](tip403.md) §4.6; the pseudocode below restates it for reference and matches it step for step.

```python
def release_blocked_funds(originator, receiver, to, amount, recovery_mode, recovery_auth):
    check_not_paused()
    dest = resolve(to)
    validate(dest)
    if recovery_mode.is_reroute(to, receiver):
        subject = recovery_mode.policy_subject(originator, receiver)
        ensure_transfer_authorized(subject, dest.target)
        if TIP403Registry.validate_receive_policy(T.address, subject, dest.target) is not None:
            fail(PolicyForbids())
        acct = recovery_mode.spending_account(recovery_auth)
        if acct is not None: check_and_update_spending_limit(acct, amount)
    else:
        ensure_authorized_as([(dest.target, RECIPIENT)])
    _transfer(RECEIVE_POLICY_GUARD_ADDRESS, dest, amount)         # Transfer(guard, to)
    if hop_event(dest, amount): LOG(hop_event(dest, amount))
```

### 9.5 Other internal helpers used by callers

- `ensure_transfer_authorized(frm, to)` and `ensure_authorized_as(pairs)` (§6.4), used by the DEX and the channel reserve.
- `transfer(sender, to, amount)`, `transfer_from(...)` invoked natively with a precompile as `msg_sender` (§7.2 semantics without the §3.1 entry steps), used by the DEX, the guard and the pre-T12 channel reserve.
- `ensure_receive_policy_authorized(sender, receiver)`: `fail(PolicyForbids())` if `TIP403Registry.validate_receive_policy(T.address, sender, receiver)` reports a block.
- `increment_balance` / `decrement_balance` (§6.6), used by the fee manager and DEX where their chapters say so.
- Currency check for fee tokens: `InvalidToken()` if the address is not prefixed, `InvalidCurrency()` if `STR_READ(4) != "USD"` ([fee-manager.md](fee-manager.md)).

## 10. TIP20Factory

The factory precompile at `TIP20_FACTORY_ADDRESS` (system precompile from genesis; its account carries code `0xEF` from the genesis allocation) creates tokens. It has no storage of its own.

### 10.1 ABI

| Function | Selector | Kind | Dispatched from |
|---|---|---|---|
| `createToken(string name, string symbol, string currency, address quoteToken, address admin, bytes32 salt) returns (address)` | `0x68130445` | mutate | Genesis |
| `createToken(string name, string symbol, string currency, address quoteToken, address admin, bytes32 salt, string logoURI) returns (address)` | `0x5323d222` | mutate | T5 |
| `isTIP20(address token) returns (bool)` | `0x35ec42c9` | view | Genesis |
| `getTokenAddress(address sender, bytes32 salt) returns (address)` | `0x9ed7cd64` | view | Genesis |

Event (emitted by the factory address): `TokenCreated(address indexed token, string name, string symbol, string currency, address quoteToken, address admin, bytes32 salt)`, topic0 `0x44f7b8011db3e3647a530b4ff635726de5fafc8fa8ad10f0f31c0eb9dd52fc65`.

Errors: `AddressReserved()` `0x98387502`, `AddressNotReserved()` `0xa3503be9`, `InvalidQuoteToken()` `0xd15b4fe2` (same selector as the TIP-20 error, which is what is actually returned), `TokenAlreadyExists(address token)` `0x15ef3a57`. TIP-20 errors (`InvalidToken`, `LogoURITooLong`, `InvalidLogoURI`) also surface.

The factory performs the §3.1 input-cost charge and dispatch but no initialization check.

> **Resolved conflict C-T20-03**: the TIP-20 docs' factory interface omits `AddressNotReserved` and `TokenAlreadyExists`. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-t20-03).

### 10.2 Address derivation

```python
def compute_tip20_address(sender: address, salt: bytes32) -> (address, uint64):
    h = keccak256(abi.encode(sender, salt))       # 64 bytes: 12 zero bytes ‖ sender ‖ salt. NOT metered.
    id = be_uint64(h[0:8])                        # the most significant 8 bytes of the hash
    return (tip20_address(id), id)

def get_token_address(sender, salt) -> address:   # view
    (a, id) = compute_tip20_address(sender, salt)
    if id < RESERVED_SIZE: fail(AddressReserved())
    return a
```

`getTokenAddress` costs only the input charge.

> **Resolved conflict C-T20-02**: the docs' `AddressReserved` comment says "lowerBytes < 1000"; the reserved range is ids `< 1024`. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-t20-02).

### 10.3 createToken

```python
def is_tip20(a) -> bool:
    if not is_tip20_prefix(a): return False       # no gas
    return ACCOUNT_READ(a).code_hash != KECCAK_EMPTY

def create_token(sender, name, symbol, currency, quote, admin, salt) -> address:
    (token, id) = compute_tip20_address(sender, salt)                  # unmetered
    if is_tip20(token): fail(TokenAlreadyExists(token))                # 1: ACCOUNT_READ(token)
    if not is_tip20(quote): fail(InvalidQuoteToken())                  # 2: ACCOUNT_READ(quote) if prefixed
    if currency == "USD" and STR_READ(quote, 4) != "USD":              # 3
        fail(InvalidQuoteToken())
    if id < RESERVED_SIZE: fail(AddressReserved())                     # 4 (after the quote checks)
    initialize(token, sender, name, symbol, currency, quote, admin)    # 5: §10.5
    LOG(TokenCreated(token, name, symbol, currency, quote, admin, salt))   # 6: from the factory
    return token
```

`name`, `symbol` and `currency` are not validated (any length and content; `currency` need not be an ISO 4217 code). `admin` may be any address, including zero.

### 10.4 createToken with logoURI (from T5)

```python
def create_token_with_logo(sender, name, symbol, currency, quote, admin, salt, logo_uri) -> address:
    if logo_uri != "": validate_logo_uri(logo_uri)                    # §7.12, before anything else
    token = create_token(sender, name, symbol, currency, quote, admin, salt)
    if logo_uri != "":
        write_logo_uri(token, updater=sender, uri=logo_uri)           # STR_WRITE(token, 5), LOG LogoURIUpdated from the token
    return token
```

With an empty `logo_uri` it behaves exactly like the 6-argument form (no `LogoURIUpdated`).

### 10.5 Token initialization

```python
def initialize(token, msg_sender, name, symbol, currency, quote, admin):
    SET_CODE(token, 0xEF)                                             # code deposit for 1 byte
    STR_WRITE(token, 2, name)
    STR_WRITE(token, 3, symbol)
    STR_WRITE(token, 4, currency)
    SSTORE(token, 6, quote)                                           # quoteToken
    RMW(token, 7, nextQuoteToken = quote)
    SSTORE(token, 13, U128_MAX)                                       # supplyCap
    if is_active(T9): TIP403Registry.set_token_transfer_policy(token, ALLOW_ALL_POLICY_ID)   # slot 7 policy bytes stay 0
    else:             RMW(token, 7, transferPolicyId = ALLOW_ALL_POLICY_ID)
    SSTORE(token, roleAdmins[UNGRANTABLE_ROLE], UNGRANTABLE_ROLE)
    SSTORE(token, roles[admin][DEFAULT_ADMIN_ROLE], 1)
    LOG(token, RoleMembershipUpdated(DEFAULT_ADMIN_ROLE, admin, msg_sender, True))
```

`paused`, `totalSupply`, `logoURI`, balances and reward state are left zero. The code marker `0xEF` is what makes the token "initialized" (§3.2) and what `isTIP20` observes; it also makes `EXTCODESIZE(token) = 1` and `EXTCODEHASH(token) = keccak256(0xEF)`.

The log order for a successful `createToken` is: `RoleMembershipUpdated` (token) → `TokenCreated` (factory) [→ `LogoURIUpdated` (token), T5 overload with non-empty URI].

### 10.6 Reserved-address creation and genesis tokens

Tokens with id `< 1024` are created only outside block execution, by genesis construction ([../04-state-and-genesis.md](../04-state-and-genesis.md)), with this procedure:

```python
def create_token_reserved_address(address, name, symbol, currency, quote, admin):
    if not is_tip20_prefix(address): fail(InvalidToken())
    if is_tip20(address): fail(TokenAlreadyExists(address))
    if quote != 0:
        if address == PATH_USD_ADDRESS or not is_tip20(quote): fail(InvalidQuoteToken())
        if currency == "USD" and STR_READ(quote, 4) != "USD": fail(InvalidQuoteToken())
    if tip20_id(address) >= RESERVED_SIZE: fail(AddressNotReserved())
    initialize(address, msg_sender=admin, name, symbol, currency, quote, admin)
    LOG(factory, TokenCreated(address, name, symbol, currency, quote, admin, salt=ZERO32))
```

No block-execution path calls it at T13 or earlier. A client MUST take genesis TIP-20 state verbatim from the genesis allocation. Mainnet genesis contains TIP-20 accounts at `0x20C0000000000000000000000000000000000000` (pathUSD: name and symbol `"pathUSD"`, currency `"USD"`, quote token 0, policy 1, supply cap `U128_MAX`) and `0x20c00000000000000000000016c6514b53947fdc`, plus the factory account, each with code `0xEF`.

## 11. TIP20ChannelReserve (TIP-1034)

A system precompile at `TIP20_CHANNEL_RESERVE_ADDRESS = 0x4D50500000000000000000000000000000000000`, active from T5 (before T5 the address is an ordinary account). Its 0xEF code marker is installed at the T5 boundary ([../05-block-execution.md](../05-block-execution.md)). It holds payer deposits in TIP-20 tokens and pays the payee against cumulative EIP-712 vouchers.

The reserve performs the §3.1 input-cost charge and dispatch but no initialization check. From T7, every mutating entrypoint (`open`, `settle`, `topUp`, `close`, `requestClose`, `withdraw`) first sets the reserve's TIP-1060 storage-credit mode to `Preserve` (`StorageCredits.set_mode(TIP20_CHANNEL_RESERVE_ADDRESS, Preserve)`: a transient read and write on the StorageCredits contract, [account-keychain.md](account-keychain.md)) before any step of §11.6 runs.

### 11.1 Constants

| Name | Value |
|---|---|
| `CLOSE_GRACE_PERIOD` | `900` seconds |
| `VOUCHER_TYPEHASH` | keccak256("Voucher(bytes32 channelId,uint96 cumulativeAmount)") = `0x4730b4b2fe8de522475e80e010877c5b58ad10eb07fd0436615ee123f743bbe8` |
| `NAME_HASH` | keccak256("TIP20 Channel Reserve") = `0x131992c67b15deae2fea2ee6e0448ff6217787c4722ce1b46fba946132054433` |
| `VERSION_HASH` | keccak256("1") |
| domain separator | `keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, uint256(chain_id), TIP20_CHANNEL_RESERVE_ADDRESS))` |
| domain separator, chain 4217 | `0x6465ffa0b0c1e7cfc1a894ba54d79615bc06fd7cc9cfec558f3df82189d17367` |
| domain separator, chain 42431 | `0xa3aa475070603a80823360e5a4a0d3b4fe2cd4e82a109ee3c21a4640a199688d` |

Computing the domain separator is **not** metered on any chain.

### 11.2 ABI

`ChannelDescriptor` is the tuple `(address payer, address payee, address operator, address token, bytes32 salt, address authorizedSigner, bytes32 expiringNonceHash)`. `ChannelState` is `(uint96 settled, uint96 deposit, uint32 closeRequestedAt)`. `Channel` is `(ChannelDescriptor descriptor, ChannelState state)`.

| Function | Selector | Kind | From |
|---|---|---|---|
| `CLOSE_GRACE_PERIOD() returns (uint64)` | `0x956c8327` | view | T5 |
| `VOUCHER_TYPEHASH() returns (bytes32)` | `0x94739e87` | view | T5 |
| `open(address payee, address operator, address token, uint96 deposit, bytes32 salt, address authorizedSigner) returns (bytes32 channelId)` | `0xedc53b00` | mutate | T5 |
| `settle(ChannelDescriptor descriptor, uint96 cumulativeAmount, bytes signature)` | `0x97fb5104` | mutate | T5 |
| `topUp(ChannelDescriptor descriptor, uint96 additionalDeposit)` | `0xdc48471e` | mutate | T5 |
| `close(ChannelDescriptor descriptor, uint96 cumulativeAmount, uint96 captureAmount, bytes signature)` | `0x73b57f74` | mutate | T5 |
| `requestClose(ChannelDescriptor descriptor)` | `0x675402e5` | mutate | T5 |
| `withdraw(ChannelDescriptor descriptor)` | `0x41e2c664` | mutate | T5 |
| `getChannel(ChannelDescriptor descriptor) returns (Channel)` | `0xeef95313` | view | T5 |
| `getChannelState(bytes32 channelId) returns (ChannelState)` | `0xd18da8b1` | view | T5 |
| `getChannelStatesBatch(bytes32[] channelIds) returns (ChannelState[])` | `0xd1f4cda2` | view | T5 |
| `computeChannelId(address payer, address payee, address operator, address token, bytes32 salt, address authorizedSigner, bytes32 expiringNonceHash) returns (bytes32)` | `0x185eeeac` | view | T5 |
| `getVoucherDigest(bytes32 channelId, uint96 cumulativeAmount) returns (bytes32)` | `0xf3b349e8` | view | T5 |
| `domainSeparator() returns (bytes32)` | `0xf698da25` | view | T5 |
| `storageCredits(address payer) returns (uint64)` | `0x4d65338b` | view | T7 |

Selectors are computed over the canonical signature with the descriptor written as the tuple type, for example `settle((address,address,address,address,bytes32,address,bytes32),uint96,bytes)`.

Events (emitted by the reserve address):

| Event | topic0 | Indexed | Data |
|---|---|---|---|
| `ChannelOpened(bytes32 channelId, address payer, address payee, address operator, address token, address authorizedSigner, bytes32 salt, bytes32 expiringNonceHash, uint96 deposit)` | `0xdebaba36f0e9c7978f536fed432d9360b1f9646d7ca88531c34c3eae43f154a7` | channelId, payer, payee | operator, token, authorizedSigner, salt, expiringNonceHash, deposit |
| `Settled(bytes32 channelId, address payer, address payee, uint96 cumulativeAmount, uint96 deltaPaid, uint96 newSettled)` | `0x11c4e4c79ad8802431b44c15047ed1ddb82fbfc1abd452c765f7ee3990df1399` | channelId, payer, payee | cumulativeAmount, deltaPaid, newSettled |
| `TopUp(bytes32 channelId, address payer, address payee, uint96 additionalDeposit, uint96 newDeposit)` | `0x2a96f534665f3150977dd4c35d91373c74030288edbb3cf83c527dd25012364f` | channelId, payer, payee | additionalDeposit, newDeposit |
| `CloseRequested(bytes32 channelId, address payer, address payee, uint256 closeGraceEnd)` | `0xf5a36fc00a96cbb9cf1f8f59299165e1d8ffffe94396d82904b4da524d16bbce` | channelId, payer, payee | closeGraceEnd |
| `ChannelClosed(bytes32 channelId, address payer, address payee, uint96 settledToPayee, uint96 refundedToPayer)` | `0x5613aed96d5bf39f928408dbe1d4143490b9bb5957eac2dd8e69b5dc4b2206e6` | channelId, payer, payee | settledToPayee, refundedToPayer |
| `CloseRequestCancelled(bytes32 channelId, address payer, address payee)` | `0x6bbcbc59913c43e567847487b95410b0b65cf253531b1c6505b21f8359c838fe` | channelId, payer, payee | (none) |

Errors:

| Error | Selector |
|---|---|
| `ChannelAlreadyExists()` | `0x0ec0f149` |
| `ChannelNotFound()` | `0x1e07dd94` |
| `NotPayer()` | `0x1435e357` |
| `NotPayeeOrOperator()` | `0x626a2a3d` |
| `InvalidPayee()` | `0xb387a238` |
| `ZeroDeposit()` | `0x56316e87` |
| `ExpiringNonceHashNotSet()` | `0x102f04a9` |
| `InvalidSignature()` | `0x8baa579f` |
| `AmountExceedsDeposit()` | `0xbd0d7138` |
| `AmountNotIncreasing()` | `0x32d2c1a3` |
| `CaptureAmountInvalid()` | `0xc91833a1` |
| `CloseNotReady()` | `0x02b81e29` |
| `DepositOverflow()` | `0x1132981b` |
| `RootKeyRetired(address)` | `0x5eb7b977` |

`RootKeyRetired` is raised only from T14. TIP-20 errors (for example `InvalidToken()` `0xc1ab6dc1` for a non-prefixed token, `PolicyForbids()`, `ContractPaused()`, `InsufficientBalance`) and AddressRegistry, AccountKeychain and ReceivePolicyGuard errors bubble up unchanged.

> **Resolved conflict C-T20-09**: TIP-1034 requires an interface identical to its reference file and on-chain storage of only `ChannelState`; from T7 the code adds the `storageCredits` view and the per-payer credit mapping (§11.3, §11.9). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-t20-09).

### 11.3 Storage layout

Persistent storage of the reserve account:

| Slot | Name | Type |
|---|---|---|
| 0 | `channelStates` | `mapping(bytes32 channelId => PackedChannelState)`, one slot per channel at `keccak256(channelId ‖ pad32(0))` |
| 1 | `channelStorageCredits` | `mapping(address payer => uint64)`, full slot at `keccak256(pad32(payer) ‖ pad32(1))` (written from T7 only) |

Transient storage of the reserve account (same slot numbering; cleared at the end of every transaction):

| Slot | Name | Type |
|---|---|---|
| 2 | `openedThisTx` | `mapping(bytes32 channelId => bool)` at `keccak256(channelId ‖ pad32(2))` |
| 3 | `channelOpenContextHash` | `bytes32` at slot 3 |

`PackedChannelState` packs into one slot, low-order first:

| Bits | Bytes (from the low end) | Field |
|---|---|---|
| 0..95 | 0..11 | `settled` (uint96) |
| 96..191 | 12..23 | `deposit` (uint96) |
| 192..223 | 24..27 | `closeRequestedAt` (uint32) |
| 224..231 | 28 | `usesLogicalReceivePolicySender` (bool, 0 or 1) |
| 232..255 | 29..31 | zero |

A channel exists iff `deposit != 0`. Every state write writes the whole slot with one `SSTORE` and no prior read (the reserve exists only from T5, after T4's zero-initialised struct writes). Deleting a channel writes 0 to the slot. `usesLogicalReceivePolicySender` is written as `is_active(T12)` when the channel is opened and preserved by every later write; channels opened before T12 read it as `false`.

```python
def receive_policy_sender(state, payer) -> address:
    return payer if state.usesLogicalReceivePolicySender else TIP20_CHANNEL_RESERVE_ADDRESS
```

> **Resolved conflict C-T20-08**: TIP-1034 declares bits 224..255 of the packed state reserved and always zero; from T12 byte 28 holds the logical-receive-policy-sender flag. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-t20-08).

### 11.4 Channel id, open context hash and voucher digest

```python
RESERVE = TIP20_CHANNEL_RESERVE_ADDRESS

def channel_id(payer, payee, operator, token, salt, signer, nonce_hash) -> bytes32:
    return KECCAK(288)(abi.encode(payer, payee, operator, token, salt, signer, nonce_hash,
                                  RESERVE, uint256(chain_id)))

def voucher_digest(cid, cumulative: uint96) -> bytes32:
    sh = KECCAK(96)(abi.encode(VOUCHER_TYPEHASH, cid, cumulative))
    return KECCAK(66)(0x19 ‖ 0x01 ‖ domain_separator ‖ sh)        # domain separator unmetered
```

**Open context hash.** At the start of every transaction (every type), before fee-token resolution and outside any metered frame, the transaction handler writes transient slot 3 of the reserve with the transaction's sender-scoped unique identifier `keccak256(encode_for_signing(tx) ‖ sender)` (the same identifier used for expiring-nonce replay protection; [../06-transactions-and-fees.md](../06-transactions-and-fees.md) defines `encode_for_signing` per type). The write costs the transaction no gas. All `open` calls in one transaction therefore share one `expiringNonceHash`, and `openedThisTx` rejects a second `open` of the same id in the same transaction even after a close or withdraw.

### 11.5 Voucher validation

```python
def expected_signer(d): return d.payer if d.authorizedSigner == 0 else d.authorizedSigner

def validate_voucher(d, cid, cumulative, signature):
    digest = voucher_digest(cid, cumulative)
    try:    signer = SignatureVerifier.recover(digest, signature)    # native call, account-keychain.md
    except: fail(InvalidSignature())                                 # every recover failure maps here
    if signer != expected_signer(d): fail(InvalidSignature())
```

`SignatureVerifier.recover` (TIP-1020) accepts the Tempo signature encodings it supports and rejects keychain wrapper signatures; its rules and gas are in [account-keychain.md](account-keychain.md).

### 11.6 Entrypoints

Helpers: `cid(d)` is `channel_id` over the descriptor's seven fields. `load_existing(id)`: `s = SLOAD(channelStates[id])`; if `s.deposit == 0`: `fail(ChannelNotFound())`. `token_of(a)`: `fail(InvalidToken())` if `a` lacks the TIP-20 prefix (no gas); otherwise the token (no initialization check, §3.2). `now` is `block.timestamp`. Calls on `T` are the TIP-20 internal procedures of §6 and §9, run natively (§1.3).

#### open

```python
def open(msg_sender, payee, operator, token, deposit, salt, authorized_signer) -> bytes32:
    if payee == 0 or is_tip20_prefix(payee) or (payee is virtual and (operator == 0 or operator is virtual)):
        fail(InvalidPayee())                                              # 1
    T = token_of(token)                                                   # 2
    if deposit == 0: fail(ZeroDeposit())                                  # 3
    # (from T14 only: retired-root check of the voucher signer; no operation before T14)
    h = TLOAD(3)                                                          # 4
    if h == 0: fail(ExpiringNonceHashNotSet())
    id = channel_id(msg_sender, payee, operator, token, salt, authorized_signer, h)   # 5
    if SLOAD(channelStates[id]).deposit != 0 or TLOAD(openedThisTx[id]) != 0:        # 6: TLOAD skipped if the SLOAD shows a channel
        fail(ChannelAlreadyExists())
    if is_active(T12):                                                    # 7
        p = resolve(payee).target
        T.ensure_transfer_authorized(msg_sender, p)                       #   payer as sender, payee as recipient
        T.ensure_receive_policy_authorized(msg_sender, p)
        T.channel_reserve_transfer(msg_sender, direct(RESERVE), deposit, receive_policy_sender=msg_sender)
    else:
        T.ensure_authorized_as([(resolve(payee).target, RECIPIENT)])
        T.system_transfer_from(RESERVE, msg_sender, deposit)              # §9.1
    write_state_spending_credit(msg_sender, id,                           # 8: §11.9
        State(settled=0, deposit=deposit, closeRequestedAt=0, usesLogicalReceivePolicySender=is_active(T12)))
    TSTORE(openedThisTx[id], 1)                                           # 9
    LOG(ChannelOpened(id, msg_sender, payee, operator, token, authorized_signer, salt, h, deposit))   # 10
    return id
```

The descriptor keeps `payee` as given (possibly virtual); every payout resolves it again.

#### settle

```python
def settle(msg_sender, d, cumulative, signature):
    id = cid(d)
    s = load_existing(id)
    if msg_sender != d.payee and (d.operator == 0 or msg_sender != d.operator): fail(NotPayeeOrOperator())
    if cumulative > s.deposit: fail(AmountExceedsDeposit())
    if cumulative <= s.settled: fail(AmountNotIncreasing())
    validate_voucher(d, id, cumulative, signature)
    delta = cumulative - s.settled
    T = token_of(d.token)
    if is_active(T12):
        p = resolve(d.payee)
        T.ensure_transfer_authorized(d.payer, p.target)
        T.channel_reserve_transfer(RESERVE, p, delta, receive_policy_sender(s, d.payer))
        s.settled = cumulative; SSTORE(channelStates[id], s)
    else:
        T.ensure_authorized_as([(d.payer, SENDER)])
        s.settled = cumulative; SSTORE(channelStates[id], s)              # written before the payout
        T.transfer(msg_sender=RESERVE, to=d.payee, amount=delta)          # §7.2; from T6 may divert to the guard
    LOG(Settled(id, d.payer, d.payee, cumulative, delta, cumulative))
```

Settlement neither cancels nor extends a pending close request.

#### topUp

```python
def top_up(msg_sender, d, additional):
    id = cid(d); s = load_existing(id)
    if msg_sender != d.payer: fail(NotPayer())
    had_close = s.closeRequestedAt != 0
    if additional == 0 and not had_close: return                         # no write, no event
    if additional != 0:
        # (from T14 only: retired-root check of expected_signer(d))
        if s.deposit + additional >= 2**96: fail(DepositOverflow())
        s.deposit += additional
        T = token_of(d.token)
        if is_active(T12):
            p = resolve(d.payee).target
            T.ensure_transfer_authorized(msg_sender, p)
            T.ensure_receive_policy_authorized(receive_policy_sender(s, msg_sender), p)
            T.channel_reserve_transfer(msg_sender, direct(RESERVE), additional, receive_policy_sender=msg_sender)
        else:
            T.ensure_authorized_as([(resolve(d.payee).target, RECIPIENT)])
            T.system_transfer_from(RESERVE, msg_sender, additional)
    if had_close: s.closeRequestedAt = 0
    SSTORE(channelStates[id], s)
    if had_close: LOG(CloseRequestCancelled(id, d.payer, d.payee))
    LOG(TopUp(id, d.payer, d.payee, additional, s.deposit))
```

#### requestClose

```python
def request_close(msg_sender, d):
    id = cid(d); s = load_existing(id)
    if msg_sender != d.payer: fail(NotPayer())
    if s.closeRequestedAt != 0: return                                   # idempotent: no write, no event
    s.closeRequestedAt = min(now, 2**32 - 1)
    SSTORE(channelStates[id], s)
    LOG(CloseRequested(id, d.payer, d.payee, uint256(now + CLOSE_GRACE_PERIOD)))
```

#### close

```python
def close(msg_sender, d, cumulative, capture, signature):
    id = cid(d); s = load_existing(id)
    if msg_sender != d.payee and (d.operator == 0 or msg_sender != d.operator): fail(NotPayeeOrOperator())
    if capture < s.settled or capture > cumulative: fail(CaptureAmountInvalid())
    if capture > s.deposit: fail(AmountExceedsDeposit())
    if capture > s.settled: validate_voucher(d, id, cumulative, signature)   # otherwise the signature is ignored
    delta = capture - s.settled
    refund = s.deposit - capture
    if is_active(T12):
        T = token_of(d.token)
        if delta != 0:
            p = resolve(d.payee)
            T.ensure_transfer_authorized(d.payer, p.target)
            T.channel_reserve_transfer(RESERVE, p, delta, receive_policy_sender(s, d.payer))
        if refund != 0:
            T.channel_reserve_transfer(RESERVE, resolve(d.payer), refund, receive_policy_sender=RESERVE)
        delete_state_and_credit_payer(id, d.payer)                       # after both deliveries
    else:
        delete_state_and_credit_payer(id, d.payer)                       # before the payouts
        T = token_of(d.token)
        if delta != 0:
            T.ensure_authorized_as([(d.payer, SENDER)])
            T.transfer(msg_sender=RESERVE, to=d.payee, amount=delta)
        if refund != 0:
            T.transfer(msg_sender=RESERVE, to=d.payer, amount=refund)
    LOG(ChannelClosed(id, d.payer, d.payee, capture, refund))
```

#### withdraw

```python
def withdraw(msg_sender, d):
    id = cid(d); s = load_existing(id)
    if msg_sender != d.payer: fail(NotPayer())
    if s.closeRequestedAt == 0 or now < s.closeRequestedAt + CLOSE_GRACE_PERIOD: fail(CloseNotReady())
    refund = s.deposit - s.settled
    if is_active(T12):
        if refund != 0:
            token_of(d.token).channel_reserve_transfer(RESERVE, resolve(d.payer), refund, receive_policy_sender=RESERVE)
        delete_state_and_credit_payer(id, d.payer)
    else:
        delete_state_and_credit_payer(id, d.payer)
        if refund != 0:
            token_of(d.token).transfer(msg_sender=RESERVE, to=d.payer, amount=refund)
    LOG(ChannelClosed(id, d.payer, d.payee, s.settled, refund))
```

The grace comparison is `now >= closeRequestedAt + 900` evaluated in 64-bit arithmetic.

#### Views

| Function | Operations |
|---|---|
| `CLOSE_GRACE_PERIOD` (returns 900), `VOUCHER_TYPEHASH`, `domainSeparator` | none |
| `getChannel(d)` | `KECCAK(288)`, `SLOAD(channelStates[id])`; returns the descriptor as given plus the state (zero if absent) |
| `getChannelState(id)` | `SLOAD(channelStates[id])` |
| `getChannelStatesBatch(ids)` | one `SLOAD` per id, in order |
| `computeChannelId(...)` | `KECCAK(288)` |
| `getVoucherDigest(id, c)` | `KECCAK(96)`, `KECCAK(66)` |
| `storageCredits(p)` (T7) | `SLOAD(channelStorageCredits[p])` |

The views return `(settled, deposit, closeRequestedAt)` only; the T12 flag is not exposed.

### 11.7 Pre-T12 token movement (T5 to T11)

Before T12, payouts (`settle`, `close`, `withdraw`) call the token's `transfer` natively with the reserve as `msg_sender` (§7.2): the recipient is resolved (a virtual payee is allowed), TIP-403 is checked for the physical pair (reserve as sender, recipient as recipient), the reserve's spending-limit hook runs, and from T6 a receive-policy block **diverts** the payout to the ReceivePolicyGuard while the channel accounting still records it as paid. Deposits (`open`, `topUp`) use `system_transfer_from` (§9.1): physical TIP-403 checks with the payer as sender and the reserve as recipient, the payer's spending limit, and from T6 the reserve's own receive policy. The reserve additionally checks the resolved payee as TIP-403 recipient before deposits and the payer as TIP-403 sender before captures. In every pre-T12 path the channel-state write or delete happens **before** the token movement.

### 11.8 T12 logical-authorization path (TIP-1095)

From T12, for **every** channel regardless of when it was opened:

- deposits and captures check TIP-403 for the logical pair (payer as sender, resolved payee as recipient) and move funds with `channel_reserve_transfer` (§9.3), which applies pause, recipient validity, the spending limit of the physical sender and the receive policy, but no TIP-403 check involving the reserve;
- refunds bypass TIP-403 and present the reserve as receive-policy sender;
- a receive-policy block reverts the operation (no guard receipt);
- terminal state is deleted only after every delivery succeeds, and `settle` writes state after its payout.

Only the receive-policy sender used for the payee preflight in `topUp` and for captures depends on the per-channel flag (§11.3): the payer for channels opened from T12, the reserve for older channels. `open` always preflights with the payer.

> **Resolved conflict C-T20-10**: TIP-1095 says its behaviour activates for channels opened at or after T12; the code applies the T12 authorization and delivery path to all channels from T12 and keeps only the receive-policy sender per channel. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-t20-10).

### 11.9 Channel storage credits (from T7)

From T7 the reserve attributes TIP-1060 storage credits earned by deleting channel-state slots to the channel's payer, and spends them when the same payer opens a new channel. The credits are held by the reserve address in the StorageCredits precompile; `channelStorageCredits[payer]` records how many belong to each payer. The semantics of `Preserve` and `Direct` modes, budgets, minting on slot deletion and spending on slot creation, and the gas of StorageCredits reads and transient writes, are in [account-keychain.md](account-keychain.md). The helpers used here:

- `track_minted(owner, f)`: before T7, run `f` and return 0. Otherwise `b0 = balance(owner)` (an `SLOAD` on StorageCredits), run `f`, `b1 = balance(owner)` (`SLOAD`); `b1 < b0` is an invariant violation that cannot occur in a valid chain; return `b1 - b0`.
- `with_budget(owner, limit, f)` with `limit > 0`: before T7, run `f` and return 0. Otherwise set `owner`'s transient credit state to mode `Direct` with budget `limit` (`TLOAD`, `TSTORE`), `b0 = balance(owner)`, run `f`, `b1 = balance(owner)`, reset the transient state to mode `Preserve` with budget 0 keeping its pending refunds (`TLOAD`, `TSTORE`), and return the signed `b1 - b0`.

```python
def credit_payer(payer, n):
    if n == 0: return
    cur = SLOAD(channelStorageCredits[payer])
    upd = min(cur + n, 2**64 - 1)                                # saturating
    if cur == 0:
        d = with_budget(RESERVE, 1, lambda: SSTORE(channelStorageCredits[payer], upd))
        assert d == -1                                           # invariant: creating the slot spends exactly one credit
    else:
        SSTORE(channelStorageCredits[payer], upd)

def delete_state_and_credit_payer(id, payer):
    n = track_minted(RESERVE, lambda: SSTORE(channelStates[id], 0))
    credit_payer(payer, n)

def write_state_spending_credit(payer, id, state):
    if not is_active(T7): SSTORE(channelStates[id], state); return
    cur = SLOAD(channelStorageCredits[payer])
    if cur == 0: SSTORE(channelStates[id], state); return
    SSTORE(channelStorageCredits[payer], 0)
    d = with_budget(RESERVE, cur, lambda: SSTORE(channelStates[id], state))
    spent = -d if d < 0 else 0
    assert spent == 1                                            # invariant
    credit_payer(payer, cur - spent)
```

Before T7, `delete_state_and_credit_payer` is a plain `SSTORE(channelStates[id], 0)` and slot 1 is never touched. The `assert`s are internal invariants of a correct implementation; a mismatch is a node fault, not a revert.

### 11.10 Payment-lane classification

Channel-reserve calls are payment-lane calls for block gas accounting under the predicate in [../05-block-execution.md](../05-block-execution.md) and [../06-transactions-and-fees.md](../06-transactions-and-fees.md) (`open`, `topUp`, `requestClose`, `withdraw` by exact static length; `settle` and `close` by strict decoding, total calldata ≤ 2048 bytes and a valid Tempo signature encoding). That classification does not change the reserve's execution.

## 12. Per-fork change ledger

Every TIP-20, factory and channel-reserve change that affects block validity or post-state, Genesis through T13. Framework-wide changes (input cost, selector-revert behaviour, decoder strictness, SLOAD/SSTORE pre-charging, static-call handling, gas schedule) are in [00-framework.md](00-framework.md) and apply here too.

| Fork | Change | Section |
|---|---|---|
| Genesis | TIP-20, factory (6-argument `createToken`, `isTIP20`, `getTokenAddress`), roles, rewards, `burnBlocked` (protected: FeeManager, DEX), fee hooks, unchecked `system_transfer_from`. Mint/burn/burnBlocked ignore the pause flag; mints do not validate the recipient. | §6–§10 |
| T1C | `transfer_fee_post_tx` restores the access-key spending limit by the refund. | §9.2 |
| T2 | `permit`, `nonces`, `DOMAIN_SEPARATOR` dispatched. Sender-policy failure skips the recipient-policy lookup. | §7.4, §6.4 |
| T3 | Virtual recipients resolved through the AddressRegistry on transfer and mint paths. `mint*`, `burn*` and `burnBlocked` check the pause flag; `mint*` validates the resolved recipient. `setRewardRecipient` rejects virtual recipients. | §2.4, §6.11, §7.6, §7.7, §8.4 |
| T4 | Initialization-check failures (for example out-of-gas) propagate instead of becoming `Uninitialized`. Struct writes no longer read the packed slot first (affects `UserRewardInfo` writes). | §3.1, §5 |
| T5 | `logoURI`, `setLogoURI` and the 7-argument `createToken`. `system_transfer_from` restricted to the Implicit Approval List. Protected burn sources add TIP20ChannelReserve and the token itself. TIP20ChannelReserve activates (deposits via `system_transfer_from`, payouts via `transfer`). String writes clear stale long-string tails. | §7.12, §10.4, §9.1, §2.3, §11 |
| T6 | Receive policies: transfer and mint paths divert blocked inbounds to the ReceivePolicyGuard; transfers or mints targeting the guard revert `AddressReserved`. Guard added to protected burn sources. `release_blocked_funds` and the guard's receipt burn. | §6.9, §9.4, §7.7 |
| T7 | `distributeReward` and `setRewardRecipient` become no-ops. Reserve: TIP-1060 `Preserve` mode on mutating calls, per-payer channel storage credits, `storageCredits` view. TIP-1060 credit hook on every precompile SSTORE. | §8, §11.9 |
| T8 | Reward accrual disabled (`update_rewards` returns 0 without operations; `getPendingRewards` returns only the settled balance). `_transfer` debits with `SDEC` instead of `SLOAD` + compare + `SSTORE`. | §8.1, §6.7 |
| T9 | Token policy binding in the TIP403Registry: policy reads prefer the binding; `changeTransferPolicyId` and token creation write the binding, not slot 7. | §5.1, §7.9, §10.5 |
| T10, T11, T13 | No TIP-20, factory or reserve specific change. | |
| T12 | `burnAt` and `BURN_AT_ROLE`. Zone-portal addresses added to protected burn sources. Reserve: logical payer→payee TIP-403 authorization, refund bypass, receive-policy rejections revert, terminal state committed after delivery, per-channel receive-policy-sender flag. | §7.8, §2.3, §11.8 |

## 13. Invariants

A conforming implementation preserves these for every token, at every block:

- `totalSupply` equals the sum of all balances, counting the token's own balance (reward pool), the fee manager's, the DEX's, the channel reserve's and the guard's.
- `totalSupply <= supplyCap <= U128_MAX` after every successful `mint` and `setSupplyCap`. (Genesis state may hold any values; the cap is checked only when minting.)
- From T3, no recipient-resolving path credits the zero address, a TIP-20-prefixed address, or a virtual address.
- `system_transfer_from`, the fee hooks and `channel_reserve_transfer` never change `totalSupply`.
- From T5, `bytes(logoURI).length <= 256`.
- For every channel: `settled <= deposit < 2^96`; the reserve's token balance is at least the sum of `deposit - settled` over its channels in that token.

