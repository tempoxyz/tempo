# Precompile framework

Status: normative. Applies to Tempo mainnet (chain id 4217) from genesis through T13.

This chapter specifies the machinery shared by every Tempo native precompile: which addresses are
precompiles and from which fork, how a call reaches one, how calldata is charged and decoded, how
results and errors surface to the EVM, how precompile state is laid out in account storage, how
every storage and host primitive is metered, how precompile accounts appear in state, and how the
executor invokes precompile logic outside the EVM. Each precompile's own chapter (ABI, storage
fields, per-method algorithm in storage-access order) builds on these rules:
[tip20.md](tip20.md), [tip403.md](tip403.md), [fee-manager.md](fee-manager.md),
[stablecoin-dex.md](stablecoin-dex.md), [account-keychain.md](account-keychain.md) (also the
nonce manager, signature verifier and storage credits) and
[validator-config-and-zones.md](validator-config-and-zones.md).

Reference implementation: crates/precompiles/src/{lib.rs,dispatch.rs,error.rs,storage/**},
crates/precompiles-macros/src/**, crates/contracts/src/precompiles/mod.rs,
crates/primitives/src/address.rs, crates/hardfork/src/gas_params.rs, crates/evm/src/block.rs.

## 1. Conventions

- *Fork F active* means `header.timestamp >= activation_time(F)` as defined in
  [01-chain-and-forks.md](../01-chain-and-forks.md). Forks are totally ordered
  `Genesis < T0 < T1 < T1A < T1B < T1C < T2 < … < T13`. "From F" means "when F is active";
  "before F" means "when F is not active". `fork` below denotes the newest active fork of the
  block being executed.
- The EVM is Ethereum Osaka at every Tempo fork (see [05-block-execution.md](../05-block-execution.md));
  the per-fork differences below are Tempo's.
- Frame fields follow the call-message model of the EVM:
  - `call_target`: the address named by the CALL/CALLCODE/DELEGATECALL/STATICCALL instruction or
    by the transaction's `to`, **before** EIP-7702 delegation resolution;
  - `destination`: the account whose storage and balance the frame acts on (`call_target` for
    CALL and STATICCALL; the current frame's own address for CALLCODE and DELEGATECALL);
  - `caller`: `msg.sender` of the frame (for DELEGATECALL, the current frame's caller);
  - `input`: calldata; `gas_limit`: gas forwarded to the frame;
  - `is_static`: `caller_is_static OR kind == STATICCALL`.
- `selector(sig)` is the first 4 bytes of `keccak256(sig)`. ABI encodings follow the Solidity
  ABI specification. Custom errors are encoded as `selector(sig) || abi.encode(args)`.
- Byte offsets inside a 32-byte storage word are counted from the **least significant** byte
  (offset 0 = bits 0..7), as in Solidity's storage packing.
- Pseudocode is Python-like. `charge(g)` means: if `gas_remaining < g` raise `OutOfGas`,
  else `gas_remaining -= g`.

## 2. Precompile registry

### 2.1 Base Ethereum precompiles

Tempo uses Ethereum's built-in precompiles with a fork-dependent set:

| Tempo fork | Base set | Contents |
|---|---|---|
| Genesis … T1B (T1C not active) | **Prague** | 0x01 ECRECOVER, 0x02 SHA256, 0x03 RIPEMD160, 0x04 IDENTITY, 0x05 MODEXP (EIP-198 with EIP-2565 pricing, no EIP-7823 bound), 0x06–0x08 BN254 add/mul/pairing (EIP-196/197/1108), 0x09 BLAKE2F (EIP-152), 0x0a POINT_EVALUATION (EIP-4844), 0x0b–0x11 BLS12-381 (EIP-2537) |
| From T1C | **Osaka** | the Prague set, with MODEXP bounded by EIP-7823 and repriced by EIP-7883, plus 0x0100 P256VERIFY (EIP-7951) |

Semantics, gas and failure behaviour of each base precompile are those of execution-specs for the
named Ethereum fork. A client MUST NOT expose P256VERIFY at 0x0100, and MUST apply Prague MODEXP
rules, in any block where T1C is not active, even though the EVM itself is Osaka.

The EIP-2929 pre-warmed address set at transaction start contains exactly the base precompiles of
the active set (so 0x0100 is pre-warmed only from T1C). Tempo native precompiles (§2.2) are
**not** pre-warmed (§3.4).

### 2.2 Tempo native precompiles

A Tempo native precompile is executed natively (no EVM bytecode). The registry at T13:

| Address | Name | Active from | Chapter |
|---|---|---|---|
| `0x20C000000000000000000000` ‖ `uint64 id` (any id) | TIP-20 token (prefix-routed, §2.3) | Genesis | [tip20.md](tip20.md) |
| `0x20FC000000000000000000000000000000000000` | TIP20Factory | Genesis | [tip20.md](tip20.md) |
| `0x403C000000000000000000000000000000000000` | TIP403Registry | Genesis | [tip403.md](tip403.md) |
| `0xfeec000000000000000000000000000000000000` | TipFeeManager (incl. Fee AMM) | Genesis | [fee-manager.md](fee-manager.md) |
| `0xdec0000000000000000000000000000000000000` | StablecoinDEX | Genesis | [stablecoin-dex.md](stablecoin-dex.md) |
| `0x4E4F4E4345000000000000000000000000000000` | NonceManager | Genesis | [account-keychain.md](account-keychain.md) |
| `0xAAAAAAAA00000000000000000000000000000000` | AccountKeychain | Genesis | [account-keychain.md](account-keychain.md) |
| `0xCCCCCCCC00000000000000000000000000000000` | ValidatorConfig (v1) | Genesis | [validator-config-and-zones.md](validator-config-and-zones.md) |
| `0xCCCCCCCC00000000000000000000000000000001` | ValidatorConfigV2 | Genesis (routed); functional from T2 (§2.5) | [validator-config-and-zones.md](validator-config-and-zones.md) |
| `0xFDC0000000000000000000000000000000000000` | AddressRegistry (TIP-1022 virtual addresses) | T3 | [tip403.md](tip403.md) |
| `0x5165300000000000000000000000000000000000` | SignatureVerifier | T3 | [account-keychain.md](account-keychain.md) |
| `0x4D50500000000000000000000000000000000000` | TIP20ChannelReserve | T5 | [tip20.md](tip20.md) |
| `0xB10C000000000000000000000000000000000000` | ReceivePolicyGuard | T6 | [tip403.md](tip403.md) |
| `0x1060000000000000000000000000000000000000` | StorageCredits (TIP-1060) | T7 | [account-keychain.md](account-keychain.md) |
| `0xC077E00000000000000000000000000000000000` | CurrentCommittee | T8 | [validator-config-and-zones.md](validator-config-and-zones.md) |
| `0x5AF2000000000000000000000000000000000000` | ZoneFactory | T10 | [validator-config-and-zones.md](validator-config-and-zones.md) |
| `0x5A56000000000000000000000000000000000000` | ZoneVerifier (native Nitro attestation verifier) | T13 | [validator-config-and-zones.md](validator-config-and-zones.md) |

Out of scope: `0xAACC000000000000000000000000000000000000` (ConfigurableAccount) is routed only
from T14. A T13 client MUST treat it as an ordinary account.

### 2.3 TIP-20 prefix routing

`TIP20_PREFIX = 0x20C000000000000000000000` (12 bytes). An address `a` is a *TIP-20 address*
iff `a[0:12] == TIP20_PREFIX`; its id is `uint64(a[12:20])` (big-endian). Every TIP-20 address
is routed to the TIP-20 precompile at every fork, **whether or not a token was ever created
there**; whether a token exists is decided inside the TIP-20 precompile from the account's code
(§8.1), see [tip20.md](tip20.md). Distinguished TIP-20 addresses:

| Token | id | Address |
|---|---|---|
| pathUSD (default fee token, root DEX quote token) | 0 | `0x20C0000000000000000000000000000000000000` |
| OUSD (T13 fee-token fallback, see [06-transactions-and-fees.md](../06-transactions-and-fees.md)) | `0x6a37da5c996874be` | `0x20c0000000000000000000006a37da5c996874be` |

### 2.4 Routing predicate and precedence

```python
SYSTEM_PRECOMPILES = [  # (address, activation fork)
    (TIP403_REGISTRY, Genesis), (TIP_FEE_MANAGER, Genesis), (STABLECOIN_DEX, Genesis),
    (NONCE_MANAGER, Genesis), (ACCOUNT_KEYCHAIN, Genesis), (VALIDATOR_CONFIG, Genesis),
    (VALIDATOR_CONFIG_V2, Genesis), (TIP20_FACTORY, Genesis),
    (ADDRESS_REGISTRY, T3), (SIGNATURE_VERIFIER, T3), (TIP20_CHANNEL_RESERVE, T5),
    (RECEIVE_POLICY_GUARD, T6), (STORAGE_CREDITS, T7), (CURRENT_COMMITTEE, T8),
    (ZONE_FACTORY, T10), (ZONE_VERIFIER, T13),
]

def is_tempo_precompile(addr, fork) -> bool:
    return addr[0:12] == TIP20_PREFIX or any(a == addr and fork >= f for (a, f) in SYSTEM_PRECOMPILES)

def precompile_for(message, fork):
    t = message.call_target
    if t in base_precompile_set(fork):          # §2.1, checked first
        return BASE
    if is_tempo_precompile(t, fork):
        return TEMPO
    return None                                  # ordinary EVM code execution
```

Rules:

1. Dispatch is keyed on `call_target` only. When `precompile_for` returns `TEMPO`, the native
   precompile runs and any code stored at `call_target` (the 0xEF marker, an EIP-7702
   designator, or EVM bytecode) is ignored for execution.
2. A frame whose `call_target` is not a Tempo precompile never runs a Tempo precompile, even if
   its resolved code comes from one. In particular, a call to an account whose EIP-7702
   designator names a Tempo precompile address executes the code stored at that precompile
   address as ordinary EVM bytecode: the one-byte marker `0xEF` is an undefined opcode, so the
   frame halts exceptionally; an address with empty code makes the call succeed with empty output.
3. Value transfer for CALL/CALLCODE is performed by the EVM before dispatch, exactly as for any
   callee (see [05-block-execution.md](../05-block-execution.md)); Tempo precompiles never read
   the message value.
4. `is_tempo_precompile(addr, fork)` is also the predicate other chapters mean when they say
   "a precompile address" (e.g. receive-policy recovery authorities in [tip403.md](tip403.md)).

### 2.5 Addresses with special histories

- **ValidatorConfigV2 before T2.** `0xCCCC…01` is routed from Genesis, but while T2 is not
  active every call that passes §3.1 (any calldata, any context, including STATICCALL) charges
  the input cost (§4.1) and then returns success with empty output, with no other effect. The
  address has no account in the mainnet genesis state; its marker is installed at T2 (§8.2).
- **ZoneVerifier at T10–T12.** `0x5A56…` is not a precompile before T13. From T10 the
  activation installs EVM runtime bytecode there (a verifier stub, §8.2), which executes as an
  ordinary contract until T13. From T13 the address is a native precompile; the T13 runtime
  bytecode installed there by §8.2 stays in state (observable via EXTCODESIZE, EXTCODEHASH,
  EXTCODECOPY) but is never executed by a call to `0x5A56…`.
- **Protocol-installed EVM accounts (not precompiles).** ZonePortal implementation
  `0x5AD1000000000000000000000000000000000000`, ZoneMessenger
  `0x5A4D000000000000000000000000000000000000` and the per-zone portal proxies
  `0x5AD000000000000000000000` ‖ `uint64 zoneId` hold EVM bytecode installed by the protocol
  (§8.2, [validator-config-and-zones.md](validator-config-and-zones.md)). They execute as
  ordinary contracts; ZoneFactory writes portal storage natively.

## 3. Call-context rules

### 3.1 DELEGATECALL and CALLCODE

If a Tempo precompile is reached with `message.destination != message.call_target` (that is,
through DELEGATECALL or CALLCODE), the frame MUST revert with return data
`DelegateCallNotAllowed()` = `0x0d89438e`, **before** the input charge (§4.1) and before any other
check. The frame consumes no gas (all forwarded gas is returned to the caller). This applies to
every Tempo precompile at every fork, including ValidatorConfigV2 before T2.

> **Resolved conflict C-PFW-01**: TIP-1100 (and docs upgrades/t11) require the input charge on *every* Tempo precompile call; the code reverts DELEGATECALL/CALLCODE with no input charge. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-pfw-01).

### 3.2 Static context

A Tempo precompile frame is *static* iff `message.caller_is_static` or `message.kind ==
STATICCALL`. In a static frame:

1. *View* selectors (classified per selector in each chapter's ABI table) execute normally.
2. *Mutating* selectors are rejected **after** a successful decode (§4.3 step 6):
   - Before T12: the frame reverts with `StaticCallNotAllowed()` = `0xbeaba5b7` (gas used so far
     is charged; the rest is returned).
   - From T12: the frame halts exceptionally (as EIP-214), consuming all forwarded gas.
3. At every fork, any persistent write (SSTORE, SINC, SDEC), transient write (TSTORE), log
   emission or code write attempted by precompile logic in a static frame raises
   `StaticCallNotAllowed` internally, which halts the frame exceptionally (§5).

### 3.3 Caller and code

`msg.sender` passed to the precompile is `message.caller`. For a top-level transaction call it is
the transaction sender. Precompile logic does not read `tx.origin` from the EVM; where a
precompile needs the transaction origin it is provided through protocol-internal transient state
(see [account-keychain.md](account-keychain.md)).

### 3.4 Account warmness

Tempo native precompile addresses are not in the EIP-2929 pre-warmed set. A CALL-family
instruction targeting a Tempo precompile pays the standard Osaka account-access cost (2,600 cold,
100 warm) unless the address is already warm (transaction `to`, access list, or an earlier access
in the transaction). Inside the precompile, reading or writing the precompile's own storage marks
the precompile account warm without an additional account-access charge.

## 4. Call processing

### 4.1 Input charge (TIP-1100)

```python
def input_cost(fork, calldata_len):
    words = ceil(calldata_len / 32)
    return words * (30 if fork >= T11 else 6)
```

The charge covers all input bytes including the selector, uses overflow-checked arithmetic
(overflow = OutOfGas) and is deducted first (after the §3.1 check). If `gas_limit < input_cost` the
frame halts out-of-gas (all forwarded gas consumed). Empty calldata costs 0.

### 4.2 Duplicate-validation charge (TIP-1105)

Methods that check a list of values for duplicates (identified in their chapters: AccountKeychain
call scopes and recipients, ZoneFactory role lists) charge, from T11, `20 × n` gas (n = number of
values examined; overflow = OutOfGas) immediately before the check; before T11 they charge nothing
here and use their historical validation. Insufficient gas halts out-of-gas before the check runs.

### 4.3 Dispatch algorithm

```python
def call_tempo_precompile(p, message, fork):
    if message.destination != message.call_target:
        return REVERT(DelegateCallNotAllowed())                    # §3.1, 0 gas
    charge(input_cost(fork, len(message.input)))                    # step 1; OOG -> HALT
    r = p.pre_dispatch_checks(message.input, fork)                  # step 2
    if r is not None:
        return r
    data = message.input
    if len(data) < 4:                                               # step 3
        return REVERT(b"") if fork >= T1 else HALT()
    sel = data[0:4]
    m = p.method_by_selector(sel)
    if m is None or not m.active(fork):                             # step 4
        return REVERT(UnknownFunctionSelector(sel))
    try:
        args = abi_decode(m.inputs, data[4:], decoder_config(fork)) # step 5, §4.5
    except DecodeError:
        return REVERT(b"")
    if m.mutating and message.is_static:                           # step 6
        return REVERT(StaticCallNotAllowed()) if fork < T12 else HALT()
    return run(m, message.caller, args)                             # step 7; §5 maps results
```

- Step 2 (precompile-specific pre-dispatch checks) is empty unless a chapter defines one. The
  checks defined at T13 are: the TIP-20 "token initialized" check (an account read of the token
  address; reverts `Uninitialized()`; before T4 an error during the read, including out-of-gas, is
  treated as "not initialized"), see [tip20.md](tip20.md); the ValidatorConfigV2 pre-T2 no-op
  success (§2.5); the AccountKeychain rejection, from T11, of `authorizeKey`/`authorizeAdminKey`
  calls whose signature-type word equals the ConfigurableAccount type (empty revert), see
  [account-keychain.md](account-keychain.md); the SignatureVerifier whole-calldata length cap
  (reverts `InvalidFormat()`), see [account-keychain.md](account-keychain.md); and the
  ZoneVerifier `verify` size cap (returns `false`), see
  [validator-config-and-zones.md](validator-config-and-zones.md). Because step 2 precedes step 3,
  empty calldata to an uninitialized TIP-20 address reverts `Uninitialized()`.
- `UnknownFunctionSelector(bytes4)` has selector `0xaa4bc69a`; its return data is
  `0xaa4bc69a ‖ sel ‖ 28 zero bytes`. A selector outside its activation window (§4.4) is treated
  exactly like an unknown selector, even when the calldata is only the 4-byte selector.
- Before T1 the missing-selector halt is an exceptional halt consuming all forwarded gas. The
  unknown-selector revert applies at every fork.

### 4.4 Selector activation windows

Each method may carry an activation window: `m.active(fork)` iff `fork >= since` (when given) and
`fork < until` (when given). Methods not listed are active at every fork ≤ T13. Full ABIs are in
each chapter; the windows at T13 are:

| Precompile | Methods | Window |
|---|---|---|
| ValidatorConfig | `changeValidatorStatusByIndex` | since T1 |
| TIP-20 | `permit`, `nonces`, `DOMAIN_SEPARATOR` | since T2 |
| TIP403Registry | `isAuthorizedSender`, `isAuthorizedRecipient`, `isAuthorizedMintRecipient`, `compoundPolicyData`, `createCompoundPolicy` | since T2 |
| AccountKeychain | `authorizeKey` (T3 overload), `setAllowedCalls`, `removeAllowedCalls`, `getRemainingLimitWithPeriod`, `getAllowedCalls` | since T3 |
| AccountKeychain | `getRemainingLimit` | until T3 |
| AccountKeychain | `authorizeKey` (T5 overload), `burnKeyAuthorizationWitness`, `isKeyAuthorizationWitnessBurned` | since T5 |
| AccountKeychain | `authorizeAdminKey` | since T6 (until T14) |
| AccountKeychain | `isAdminKey` | since T6 |
| TIP-20 | `logoURI`, `setLogoURI` | since T5 |
| TIP20Factory | `createToken` (overload with logo URI) | since T5 |
| AddressRegistry | `isImplicitlyApproved` | since T5 |
| TIP403Registry | `receivePolicy`, `validateReceivePolicy`, `setReceivePolicy` | since T6 |
| SignatureVerifier | `verifyKeychain`, `verifyKeychainAdmin` | since T6 |
| StablecoinDEX | `storageCredits` | since T7 |
| TIP20ChannelReserve | `storageCredits` | since T7 |
| StablecoinDEX | `bookIndexForKey`, `bookKeyForIndex`, `setBookIndex` | since T8 |
| TIP403Registry | `tokenTransferPolicyId`, `migrateTransferPolicyIds` | since T9 |
| TIP-20 | `BURN_AT_ROLE`, `burnAt` | since T12 |

Some active selectors additionally return a method-specific error at certain forks (for example
the legacy AccountKeychain `authorizeKey` selector from T3); those are specified in the chapter.

### 4.5 ABI decoder configuration

Arguments are decoded by the Solidity ABI rules with these per-fork settings:

| Setting | Before T11 | T11 | From T12 |
|---|---|---|---|
| Decoder memory limit | 16 MiB (16,777,216 bytes) | 16 MiB | 16 MiB |
| Token validation | off | on | on |
| Canonical (strict) layout | off | on | on |
| Trailing bytes after the encoding | accepted | rejected | accepted |

- *Validation off* (before T11): each static value is taken from its 32-byte word by truncation:
  `bool` = word ≠ 0; `uintN`/`intN` = low N bits; `address` = low 20 bytes; `bytesN` = high N bytes;
  `string` = the tail bytes decoded as UTF-8 lossily (each invalid sequence replaced by U+FFFD);
  dynamic offsets are followed as given (gaps and overlaps accepted).
- *Validation on*: a word whose unused bits are not the canonical zero extension (sign extension
  for `intN`), a `bool` word > 1, or a `string` that is not valid UTF-8 is a decode error.
- *Strict layout*: every dynamic offset MUST equal the next unused position in its enclosing
  encoding (tails in order, no gaps or overlaps) and every padding byte MUST be zero.
- The memory limit bounds the decoder's allocations; exceeding it is a decode error.
- Every decode error yields an empty revert (step 5).

The reference behaviour is that of alloy-sol-types 1.7.3 `abi_decode_with_config` with
`AbiDecoderConfig::new().memory_limit(16 MiB).strict(fork >= T11).validate_allow_trailing_bytes(fork >= T12)`.

## 5. Results and errors

Precompile logic ends in one of these outcomes, mapped to the EVM frame result:

| Outcome | Frame result | Return data | Gas |
|---|---|---|---|
| Success | success | ABI-encoded return values (empty if none) | used gas charged, remainder returned |
| Domain error: any custom error of a precompile's ABI, incl. `UnknownFunctionSelector`, `DelegateCallNotAllowed`, pre-T12 `StaticCallNotAllowed` from step 6 | revert | ABI-encoded error | used gas charged, remainder returned |
| Arithmetic overflow/underflow, incl. SDEC below zero and an out-of-range value read from storage | revert | `Panic(0x11)` | as revert |
| Invalid enum discriminant read from storage | revert | `Panic(0x21)` | as revert |
| Array index out of bounds | revert | `Panic(0x32)` | as revert |
| Malformed ABI arguments; missing selector (from T1); empty reverts a chapter defines | revert | empty | as revert |
| OutOfGas: a failed `charge`, the input charge, a skipped cold load, the T12 stipend sentry | exceptional halt | empty | all forwarded gas consumed |
| `StaticCallNotAllowed` raised by a write primitive (any fork); step 6 from T12; missing selector before T1 | exceptional halt | empty | all forwarded gas consumed |
| Database failure or internal invariant violation (a stored short-string length > 31, invalid UTF-8 in a stored string, a packed lane spanning a slot boundary) | none: block processing fails | — | — |

`Panic(uint256)` has selector `0x4e487b71`. As for every EVM frame, a revert or halt undoes the
frame's state changes, transient-storage changes and logs and discards gas refunds recorded in it.
Gas charged before a revert (including the input charge and pre-dispatch checks) is not returned.

**Internal checkpoints.** Some methods take an internal checkpoint, perform several writes and
roll back to the checkpoint on a later failure while still returning normally (for example the
StablecoinDEX batch paths, [stablecoin-dex.md](stablecoin-dex.md)). From T1C the rollback undoes
all state, transient-storage and log changes since the checkpoint (gas already charged is not
returned). **Before T1C taking a checkpoint is a no-op and rolling back does nothing**: writes made
before the failure persist if the method then returns normally.

## 6. Storage model

Precompile state is ordinary account storage (and EIP-1153 transient storage) of the precompile
address, in the same state trie as every account. Each chapter declares its fields in order; slots
are derived from that declaration by the rules below. These rules reproduce Solidity's storage
layout except for mapping keys of `bytesN` (N < 32) and negative `intN` (§6.5).

### 6.1 Types and sizes

| Type | Size (bytes) | Packable | Encoding in its lane (or full word) |
|---|---|---|---|
| `bool` | 1 | yes | 0 or 1; read as lane ≠ 0 |
| `uintN` (N = 8…256) | N/8 | if < 32 | right-aligned; a full-word read whose value exceeds the type's maximum is `Panic(0x11)` |
| `intN` | N/8 | if < 32 | two's complement truncated to N bits, right-aligned (high bits zero, not sign-extended); same overflow check on the raw unsigned value |
| `address` | 20 | yes | right-aligned; read takes the low 20 bytes |
| `bytesN` (N = 1…32) | N | if < 32 | the N bytes right-aligned (low-order); read takes the low N bytes |
| enum (`uint8`-represented) | 1 | yes | discriminant as `uint8`; an unknown discriminant on read is `Panic(0x21)` |
| struct | 32 × slots | no | §6.3 |
| fixed array `T[N]` | 32 × slots | no | §6.4 |
| `T[]`, `bytes`, `string` | 32 (1 slot) | no | §6.6, §6.7 |
| `Set<T>` | 64 (2 slots) | no | §6.8 |
| mapping | 32 (1 slot, unused) | no | §6.5 |

These value encodings match Solidity's storage representation (value types, including `bytesN`,
are stored lower-order aligned). Only mapping keys deviate (§6.5).

### 6.2 Field slot allocation

Fields are processed in declaration order with a running *auto chain* (previous auto field, base
slot), initially (none, 0). A field is one of:

- `#[slot(N)]` (*manual*): placed at slot N, offset 0. It does **not** touch the auto chain; the
  next auto field continues from the previous *auto* field.
- `#[base_slot(N)]`: restarts the chain: placed at slot N, offset 0, and becomes the chain's
  previous field.
- otherwise (*auto*): with no previous auto field, it goes to the chain's base slot at offset 0.
  Else, with previous auto field `p` at `(slot_p, off_p)`:

```python
if off_p + size(p) + size(f) <= 32:   # size of a non-packable type is 32 * slots
    slot_f, off_f = slot_p, off_p + size(p)
else:
    slot_f, off_f = slot_p + slots(p), 0
```

Because non-packable sizes are multiples of 32, a struct, array, `T[]`, `bytes`, `string`, set or
mapping always starts a new slot, and the field after it starts a new slot too.

**Access context.** An auto field whose slot equals the slot of the field immediately before or
after it in declaration order is accessed *packed*: a read loads the word and extracts its lane; a
write loads the word, replaces its lane and stores the word (one metered SLOAD and one metered
SSTORE, §7). Every other field (manual fields always) is accessed *full*: a read loads the word; a
write stores the encoded value as the whole word without a prior load. Deleting a packed field
rewrites its lane to zero (SLOAD + SSTORE); deleting a full field stores zero.

### 6.3 Structs

A struct's members are allocated by §6.2 relative to the struct's base slot (member offsets start
at slot 0); its slot count is the number of slots spanned. A struct value is accessed whole or per
member:

- *Whole read*: for each run of consecutive packable members sharing a slot the word is loaded
  once; other members are read per their type.
- *Whole write*: for each run of consecutive packable members sharing a slot the lanes are
  assembled and the word is stored once. Before T4 the assembly starts from the slot's current
  word (one SLOAD per run); **from T4 it starts from zero** (no SLOAD; unused lane bytes are
  cleared). Non-packable members are written per their type.
- *Whole delete*: dynamic members are deleted per their type; then every slot that contains a
  static member is set to zero.
- *Member access* (e.g. through a mapping value handle) uses the member's own location, with the
  §6.2 packed/full rule applied among the struct's members.

> **Resolved conflict C-PFW-02**: TIP-1046 §8 says T4 removes the SLOAD for "the first packed slot" of a packed-struct store; the code removes it for every packed slot run of the struct. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-pfw-02).

### 6.4 Fixed arrays

`T[N]` starts at its base slot. If `size(T) <= 16` elements are packed `k = floor(32 / size(T))`
per slot: element `i` is in slot `base + i // k` at offset `(i % k) × size(T)`, and the array spans
`ceil(N / k)` slots. Otherwise element `i` starts at `base + i × slots(T)` (primitive elements of
17–31 bytes take one slot each). A whole read of a packed array performs one SLOAD per element; a
whole write stores each slot once (assembled from zero, no SLOAD). Single-element access to a packed
array uses packed access.

### 6.5 Mappings

`mapping(K => V)` at slot `s`: the value for key `k` lives at `keccak256(key32(k) ‖ uint256_be(s))`
and is laid out there as a fresh `V` at offset 0. A packable `V` in a mapping is always accessed
*full* (no read-modify-write). Nested mappings apply the rule recursively. `key32(k)` is the key's
own big-endian byte representation **left-padded with zero bytes** to 32 bytes:

| Key type | Key bytes | key32 | Same as Solidity `abi.encode`? |
|---|---|---|---|
| `address` | 20 bytes | 12 zero bytes ‖ address | yes |
| `bool` | 1 byte (0x00 or 0x01) | 31 zero bytes ‖ byte | yes |
| `uintN` | N/8 bytes, big-endian | zero-padded | yes |
| `bytes32` | 32 bytes | itself | yes |
| `intN`, value ≥ 0 | N/8 bytes, two's complement | zero-padded | yes |
| `intN`, value < 0 | N/8 bytes, two's complement | **zero-padded** (Solidity sign-extends with 0xff) | **no** |
| `bytesN`, N < 32 | N bytes | **left-padded**: 32−N zero bytes ‖ bytes (Solidity right-pads) | **no** |

Implementations MUST use `key32` exactly as above; Solidity's rule yields different slots and
state roots. Affected state includes the StablecoinDEX tick-indexed mappings (`int16` ticks,
negative below par), the AccountKeychain selector-scope mappings and sets (`bytes4` keys) and the
AddressRegistry master mapping (`bytes4` masterId); see those chapters. Hashes computed to derive
mapping, array and dynamic-data slots are **not** metered.

Test vectors (`s` as a 32-byte big-endian word):

| Key | Slot s | Tempo slot | Solidity slot, for contrast |
|---|---|---|---|
| `address(0x…01)` | 0 | `0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d` | same |
| `int16(5)` | 2 | `0xb98b78633099fa36ed8b8680c4f8092689e1e04080eb9cbb077ca38a14d7e384` | same |
| `int16(-1)` | 2 | `0x695395ec6a2c9d3a74f1c3d78bda956395489a2ec3ce495c3087446ede7bcc9d` | `0x38b5b2ceac7637132d27514ffcf440b705287635075af7b8bd5adcaa6a4cc5bb` |
| `bytes4(0x12345678)` | 0 | `0x2cd9aa588bc05f5645b49caf8e43cd3d5f1208ff2e6a13475a5c411eb24cbacd` | `0x2641e1b9fe9490eb98e20a130ab01d37243f32c42625d93ecdf22367d9677d2b` |

### 6.6 Dynamic arrays (`T[]`)

At slot `s`: the length is a full word at `s`; element data starts at `d = keccak256(uint256_be(s))`
with the §6.4 placement (packed iff `size(T) <= 16`).

- A length word greater than `2^32 − 1` on read is `Panic(0x11)`.
- *Whole write* of `v`: from T5, unless the chapter states the destination is fresh, load the old
  length `L` and, if `L > len(v)`, clear the old tail (packed elements: store zero to slots
  `ceil(len(v)/k)` … `ceil(L/k) − 1`; unpacked elements: delete elements `len(v)` … `L − 1` per their
  type). Then store `len(v)` at `s`, then store every data slot of `v` (packed slots assembled from
  zero). Before T5 there is no tail cleanup; stale elements past the new length remain in storage.
- *Push*: read the length `L`; write the element at index `L` (packed element: read-modify-write of
  its slot; unpacked: written as a fresh value); store `L + 1`.
- *Pop*: read the length `L` (nothing if 0); read element `L − 1`; delete it (packed: lane zeroed by
  read-modify-write); store `L − 1`.
- *Delete*: read the length `L`; store 0 at `s`; clear every data slot or element in `[0, L)`.
- Checked element access by index first reads the length; an index ≥ length is out of bounds (the
  chapter states the resulting error).

### 6.7 `bytes` and `string`

At slot `s`, Solidity's encoding: if `len <= 31` the word at `s` holds the data in its high-order
bytes and `2 × len` in its lowest byte; otherwise the word at `s` is `2 × len + 1` and the data
occupies `ceil(len / 32)` words from `keccak256(uint256_be(s))`, left-aligned, the last word
zero-padded. The lowest bit of the word at `s` selects the long form. On read a long-form length
above `2^32 − 1` is `Panic(0x11)`; a short-form length above 31, or (for `string`) invalid UTF-8, is
an invariant violation (§5).

*Write*: from T5, unless the destination is fresh, first load the word at `s`; if it is long-form
with `P` data words and the new value needs `Q < P` data words (Q = 0 for the short form), store zero
to data words `Q … P − 1`. Then store the word at `s` and (long form) each data word. Before T5 there
is no tail cleanup. *Delete*: load the word at `s`; if long-form, store zero to all its data words;
store zero at `s`.

### 6.8 Sets (OpenZeppelin EnumerableSet)

`Set<T>` at slot `s` occupies two slots: a `T[]` *values* array at `s` (§6.6) and a
`mapping(T => uint32)` *positions* at `s + 1` holding each member's 1-based index (0 = absent).

- *contains(v)*: read `positions[v]`; member iff ≠ 0.
- *insert(v)*: if contains(v) return false; read the length `L`; write `positions[v] = L + 1` (above
  `2^32 − 1` is `Panic(0x11)`); push `v`; return true.
- *remove(v)*: `p = positions[v]`; if 0 return false; read the length `L`; if `p − 1 != L − 1`: read
  `last = values[L − 1]`, write `positions[last] = p`, write `values[p − 1] = last`; delete
  `values[L − 1]`; store the length `L − 1`; delete `positions[v]`; return true.
- *write(new)* (whole replace; `new` has no duplicates): read the length `L`; for `i` in `[0, L)` read
  `values[i]` and delete its position; for each `(i, v)` of `new` write `positions[v] = i + 1` then
  `values[i] = v`; store the length `len(new)`; delete `values[i]` for `i` in `[len(new), L)`.
- *delete*: read the length `L`; for each `i < L` read `values[i]` and delete its position; then
  delete the array (§6.6).

### 6.9 Transient storage

Fields a chapter declares *transient* use EIP-1153 transient storage of the precompile address with
the same slot derivation and packing; packed transient writes are TLOAD + TSTORE. Transient storage
is cleared at the end of each transaction.

## 7. Gas metering of primitives

A precompile call's gas is the input charge plus the explicit charges its chapter names (signature
verification, duplicate validation, method-specific fixed charges) plus the cost of each primitive
below, in the exact order the method's algorithm performs them. Hashes used only to derive slots
(§6) are free.

### 7.1 Gas parameters

Tempo never enables the TIP-1016 / EIP-8037 regular/state gas split: at every fork ≤ T13 *state
gas* is zero and there is no state-gas reservoir. Parameters (unlisted ones are Osaka's):

| Parameter | Before T1 | T1 … T6 | From T7 |
|---|---|---|---|
| `WARM_READ` (warm read; also the SSTORE static part) | 100 | 100 | 100 |
| `COLD_SLOAD_EXTRA` | 2,000 | 2,000 | 2,000 |
| `COLD_SSTORE_EXTRA` | 2,100 | 2,100 | 2,100 |
| `COLD_ACCOUNT_EXTRA` | 2,500 | 2,500 | 2,500 |
| `SSTORE_SET` (clean zero→non-zero, excluding static part) | 19,900 | 250,000 | 5,000 |
| `SSTORE_RESET` (clean non-zero→other, excluding static part) | 2,800 | 2,800 | 2,800 |
| `REFUND_CLEAR` | 4,800 | 4,800 | 0 |
| `REFUND_SET_RESTORE` | 19,900 | 19,900 | 5,000 |
| `REFUND_RESET_RESTORE` | 2,800 | 2,800 | 2,800 |
| `CODE_DEPOSIT` (per byte) | 200 | 1,000 | 1,000 |
| `CALL_STIPEND` | 2,300 | 2,300 | 2,300 |
| `STORAGE_CREDIT_VALUE` (TIP-1060 hook) | — | — | 245,000 |

The transaction-level refund cap (quotient 5, then 1 from T7) is applied by the transaction
processor ([06-transactions-and-fees.md](../06-transactions-and-fees.md)).

### 7.2 Primitive costs

Warm/cold status uses the transaction's shared EIP-2929 access sets (accounts and
`(address, slot)` pairs): a slot warmed by an earlier frame, the access list or an earlier
precompile call is warm.

```python
def SLOAD(addr, key):
    if fork >= T4:
        charge(WARM_READ)
        if (addr, key) is cold and gas_remaining < COLD_SLOAD_EXTRA:
            raise OutOfGas                     # slot neither loaded nor warmed
        v, cold = load_and_warm(addr, key)
    else:
        v, cold = load_and_warm(addr, key)
        charge(WARM_READ)
    if cold:
        charge(COLD_SLOAD_EXTRA)
    return v

def SSTORE(addr, key, new):
    if is_static: raise StaticCallNotAllowed
    if fork >= T12 and gas_remaining <= CALL_STIPEND:
        raise OutOfGas                         # EIP-2200 sentry (TIP-1116 §2)
    if fork >= T4:
        charge(WARM_READ)                      # static part, pre-charged
        if (addr, key) is cold and gas_remaining < COLD_SLOAD_EXTRA:
            raise OutOfGas
    original, present, cold = write_and_warm(addr, key, new)
    if fork < T4:
        charge(WARM_READ)
    if fork >= T7 and tip1060_enabled:
        storage_credit_hook(addr, key, original, present, new)          # §7.4
    g = COLD_SSTORE_EXTRA if cold else 0
    if new != present and original == present:                          # clean, effective
        g += SSTORE_SET if original == 0 else SSTORE_RESET
    charge(g)
    if fork >= T4:
        record_refund(sstore_refund(original, present, new))           # §7.3
```

- *SINC(addr, key, δ)*: static check; `v = SLOAD(addr, key)`; `v + δ` overflowing 256 bits is
  `Panic(0x11)`; `SSTORE(addr, key, v + δ)`. *SDEC* likewise with `v − δ` (underflow is
  `Panic(0x11)`).
- *TLOAD*: `charge(100)`, then read. *TSTORE*: static check, `charge(100)`, then write.
- *LOG(addr, topics, data)*: static check, then `charge(375 + 375 × len(topics) + 8 × len(data))`
  (no memory-expansion term); the log is appended to the current logs with emitter `addr`.
- *KECCAK(data)* (only where a chapter names a metered hash, e.g. EIP-712 digests):
  `charge(30 + 6 × ceil(len(data) / 32))`.
- *ECRECOVER(digest, v, r, s)*: `charge(3,000)`; then if `v ∉ {27, 28}` the result is "invalid"
  (no 0/1 normalisation); else secp256k1 public-key recovery with y-parity `v == 28`, where a
  failure or the zero address is "invalid". The charge applies even when the result is invalid.
- *ACCOUNT_READ(addr)* (account info: code-hash or "initialized" checks, code presence): from T4
  `charge(WARM_READ)`, then if the account is cold and `gas_remaining < COLD_ACCOUNT_EXTRA` raise
  OutOfGas without loading it; before T4 load first, then `charge(WARM_READ)`. In both cases, if it
  was cold, then `charge(COLD_ACCOUNT_EXTRA)`. The account becomes warm. An absent account reads as
  empty (nonce 0, balance 0, empty code).
- *WARM_CALLER_READ(origin)*: reading the transaction origin's account, already loaded by the
  transaction, costs 0 (only where a chapter says so).
- *SET_CODE(addr, code)*: static check, `charge(CODE_DEPOSIT × len(code))`, then set the account's
  code (nonce, balance and storage kept; no account-access charge; the account becomes warm). Used by
  TIP20Factory to install the 0xEF marker (200 gas before T1, 1,000 from T1).
- *Explicit charge*: `charge(g)` as named in a chapter.

A failed `charge` raises OutOfGas and the frame halts (§5).

> **Resolved conflict C-PFW-03**: TIP-1000 gives 252,100 gas for a cold zero-to-nonzero SSTORE from T1; the code charges 100 + 2,100 + 250,000 = 252,200 (precompile SSTOREs included). Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-pfw-03).

### 7.3 SSTORE refunds

```python
def sstore_refund(original, present, new):
    if new == present:
        return 0
    if original == present and new == 0:
        return REFUND_CLEAR
    r = 0
    if original != 0:
        if present == 0:
            r -= REFUND_CLEAR
        elif new == 0:
            r += REFUND_CLEAR
    if new == original:
        r += REFUND_SET_RESTORE if original == 0 else REFUND_RESET_RESTORE
    return r
```

**Before T4, SSTOREs performed by native precompiles record no refund at all** (SSTORE opcodes in
EVM bytecode are unaffected; see [06-transactions-and-fees.md](../06-transactions-and-fees.md)).
From T4 the value above is added to the transaction's refund counter (and discarded if the frame
reverts or halts).

> **Resolved conflict C-PFW-04**: TIP-1000 (invariant 4) requires storage clearing to keep its refund for every SSTORE, including precompile-created state; the code records no refund for native-precompile SSTOREs before T4. Decided: this spec follows the implementation, and the TIP is amended in [tempoxyz/tempo#8939](https://github.com/tempoxyz/tempo/pull/8939). See [conflicts](../conflicts.md#c-pfw-04).

### 7.4 TIP-1060 storage-credit hook (from T7)

From T7 every metered precompile SSTORE (including the SSTORE inside SINC/SDEC) runs the TIP-1060
storage-credit hook after the write is journaled and the static part is charged, and before the
dynamic part (§7.2). The hook, its gas (including its own metered read of the credit balance) and
its state effects are specified in [account-keychain.md](account-keychain.md), section "Storage
credits". The framework supplies:

- `owner` = the precompile address whose storage is written, `key` = the slot, and
  `(original, present, new)`;
- `tip1060_enabled`: true in every EVM-dispatched precompile call from T7, except where a chapter
  disables it for its own writes (CurrentCommittee `setCommitteeMembers`); false in
  protocol-internal invocations (§9.1);
- the *minting enabled* flag: true unless a chapter disables it for part of a method
  ([fee-manager.md](fee-manager.md));
- the transaction-local set of non-creditable slots ([account-keychain.md](account-keychain.md));
- *Preserve mode*: from T7, after the static check and before the handler body of each of these
  methods, the storage-credit mode of the precompile's own address is set to Preserve: StablecoinDEX
  `place`, `placeFlip`, `createPair`, `withdraw`, `cancel`, `cancelStaleOrder`, `swapExactAmountIn`, `swapExactAmountOut`, `setBookIndex`
  ([stablecoin-dex.md](stablecoin-dex.md)); TIP20ChannelReserve `open`, `settle`, `topUp`, `close`, `requestClose`, `withdraw`
  ([tip20.md](tip20.md)). The step is a StorageCredits `setMode` performed natively, metered as specified in
  [account-keychain.md](account-keychain.md); before T7 it does nothing.

Writes to the StorageCredits precompile's own storage never run the hook.

## 8. Precompile account state

### 8.1 The 0xEF marker

Every live Tempo native precompile account has code equal to the single byte `0xEF`, nonce 0 and
balance 0. Its code hash is
`0x309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3`. The marker is never executed
(§2.4). It is observable through EXTCODESIZE (1), EXTCODEHASH and EXTCODECOPY. For TIP-20 addresses
it is the "token initialized" flag (TIP20Factory installs it with SET_CODE when it creates a token).
Precompiles active at genesis receive their marker and initial storage from the genesis allocation
([04-state-and-genesis.md](../04-state-and-genesis.md)).

### 8.2 Fork-boundary installs

The block executor runs the following procedure in **every** block, at the point of pre-execution
processing defined in [05-block-execution.md](../05-block-execution.md) (after that block's
Ethereum system calls: before T13 the inherited Ethereum pre-execution changes, from T13 the
EIP-2935 parent-hash system call). It writes state directly: no gas, no EVM frame, no logs, no
receipt, no effect on EIP-2929 warm sets.

```python
def install_marker(addr, storage=()):
    acct = state.get(addr)                        # None if absent
    if acct is not None and acct.code_hash != KECCAK_EMPTY:
        return                                    # already has code
    acct = acct or Account(nonce=0, balance=0)
    acct.code = b"\xef"                           # nonce and balance kept
    for (slot, value) in storage:
        state.set_storage(addr, slot, value)

def install_fork_precompile_accounts(fork):
    if fork >= T2:
        install_marker(VALIDATOR_CONFIG_V2)
    if fork >= T3:
        install_marker(SIGNATURE_VERIFIER); install_marker(ADDRESS_REGISTRY)
    if fork >= T5:
        install_marker(TIP20_CHANNEL_RESERVE)
    if fork >= T6:
        install_marker(RECEIVE_POLICY_GUARD)
    if fork >= T7:
        install_marker(STORAGE_CREDITS)
    if fork >= T8:
        install_marker(CURRENT_COMMITTEE)
    if fork >= T10 and code_hash(ZONE_FACTORY) == KECCAK_EMPTY:      # absent or empty code
        install_marker(ZONE_FACTORY, [(0, 1 | (INITIAL_FACTORY_OWNER << 32))])
        install_runtimes(T10_RUNTIMES)
    if fork >= T13 and zone_runtime_fork(genesis_fork) != T13:
        install_runtimes(T13_RUNTIMES)

def install_runtimes(runtimes):   # [(addr, code)]: ZonePortal impl, ZoneVerifier, ZoneMessenger
    for (addr, code) in runtimes:
        if code_hash(addr) != keccak256(code):
            set the code of addr to code   # nonce, balance and storage kept; created if absent
```

- `INITIAL_FACTORY_OWNER = 0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14`. The slot-0 value is the
  packed ZoneFactory configuration (1 in the low 32 bits, the owner above them), see
  [validator-config-and-zones.md](validator-config-and-zones.md).
- `T10_RUNTIMES` installs (`0x5AD1…`, ZonePortal T10 runtime), (`0x5A56…`, verifier stub runtime) and
  (`0x5A4D…`, ZoneMessenger T10 runtime); `T13_RUNTIMES` installs the T13 runtimes at the same
  addresses. The bytecodes and their hashes are pinned in
  [validator-config-and-zones.md](validator-config-and-zones.md).
- `zone_runtime_fork(genesis_fork)` is T13 only for a chain whose genesis block already has T13
  active; on mainnet it is not, so the T13 runtime check runs in every T13 block and writes only in
  the first one.
- The procedure is idempotent: after a fork's first block the checks find code present and write
  nothing.

## 9. Protocol-internal invocations

Besides EVM calls, the executor reaches precompile logic in two other ways. Call sites, inputs and
failure handling are defined in [05-block-execution.md](../05-block-execution.md),
[06-transactions-and-fees.md](../06-transactions-and-fees.md) and the precompile chapters; the
common rules are:

### 9.1 Native host invocations

The executor calls a precompile function directly (no ABI dispatch, none of the §4 steps) against
the current transaction's journaled state:

- `is_static = false`; `fork` is the block's fork; the storage model (§6) and the primitives (§7)
  are unchanged;
- gas: unless the call site states a gas limit, primitives are metered against an unbounded budget
  whose usage is discarded (they cost the transaction nothing). The AccountKeychain key-authorization
  path is the exception and is metered as stated in [account-keychain.md](account-keychain.md)
  (including the T1/T1A special gas table);
- refunds computed by §7.3 stay in that discarded budget and do not reach the transaction;
- TIP-1060: the storage-credit hook is disabled (`tip1060_enabled = false`); call sites that create
  persistent storage charge for it as their chapter specifies;
- logs emitted are appended to the current transaction's logs (and so appear in its receipt) in
  emission order;
- internal checkpoints follow §5;
- a domain error is returned to the call site, which maps it (typically to transaction invalidity or
  a fee-payment failure); a database failure or invariant violation fails block processing.

Native host invocations at T13 include: transaction-origin and channel-open-context setup,
keychain signature validation, key authorization and spending-limit accounting, 2D-nonce and
expiring-nonce checks and updates (NonceManager), fee-token resolution, pre-transaction fee
collection and post-transaction fee settlement (TipFeeManager and TIP-20 fee transfers), and
storage-credit settlement at the end of the transaction.

### 9.2 System calls

A system call is an EVM message with the caller its call site names (`caller =
0x0000000000000000000000000000000000000000` for CurrentCommittee), `value = 0`, `gas_limit = 250,000,000`, not static, executed outside
any transaction. Precompile dispatch (§2.4, §4) applies unchanged, including the input charge
against the system call's own gas. Its gas is not counted in the block's gas used, no fee is charged
and no receipt is produced; its state changes are committed. The only Tempo precompile system call at
T13 is CurrentCommittee `setCommitteeMembers(epoch, publicKeys)` in the last block of each epoch, from
T8 ([validator-config-and-zones.md](validator-config-and-zones.md),
[05-block-execution.md](../05-block-execution.md)); if it does not succeed the block is invalid.

## 10. Conformance values

| Item | Value |
|---|---|
| `DelegateCallNotAllowed()` | `0x0d89438e` |
| `StaticCallNotAllowed()` | `0xbeaba5b7` |
| `UnknownFunctionSelector(bytes4)` | `0xaa4bc69a` |
| `Panic(uint256)` | `0x4e487b71` (codes 0x11, 0x21, 0x32) |
| keccak256(0xEF), the marker's code hash | `0x309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3` |
| keccak256(uint256(0)), data start of a dynamic value at slot 0 | `0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563` |
| Input cost of a 68-byte call (e.g. `transfer(address,uint256)`) | 18 before T11; 90 from T11 |
| ABI decoder memory limit | 16,777,216 bytes |
| System call gas limit | 250,000,000 |
