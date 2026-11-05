# Account keychain, nonce manager, signature verifier and storage credits

This chapter specifies four protocol precompiles that the transaction handler uses to authorize and
pay for transactions:

| Precompile | Address | Present from | Section |
|---|---|---|---|
| AccountKeychain | `0xAAAAAAAA00000000000000000000000000000000` | Genesis (mainnet: T0) | [§1](#1-accountkeychain) |
| NonceManager | `0x4E4F4E4345000000000000000000000000000000` | Genesis (mainnet: T0) | [§2](#2-noncemanager) |
| SignatureVerifier | `0x5165300000000000000000000000000000000000` | T3 | [§3](#3-signatureverifier) |
| StorageCredits (TIP-1060) | `0x1060000000000000000000000000000000000000` | T7 | [§4](#4-storage-credits-tip-1060) |

"Present from" is the fork at which the address enters the precompile set (see
precompiles/00-framework.md for routing, and 05-block-execution.md for the `0xEF` code markers
installed at T3 and T7). A fork F is active for a block iff `header.timestamp >= F`'s activation
time, as defined in 01-chain-and-forks.md. Mainnet (chain 4217) starts at T0, so every rule below
written "from T0" holds for every mainnet block.

This chapter covers what the precompiles store and do. It does not cover when the transaction
handler calls them, the intrinsic gas it charges for key authorizations and nonces, or how their
errors map to transaction validity. Those are in 06-transactions-and-fees.md. Signature byte formats
and verification are in 03-signatures.md.

## 0. Conventions

### 0.1 Storage and gas primitives

All gas of an ABI call into these precompiles is the sum of the costs of the primitive operations it
performs, in order, plus the input charge. Each primitive's cost, including warm/cold accounting,
the T4 static pre-charge, the T12 SSTORE stipend sentry and the TIP-1060 hook, is defined in
precompiles/00-framework.md (the TIP-1060 hook itself is defined in [§4.4](#44-the-sstore-hook)).
This chapter names the primitives as follows:

| Notation | Meaning |
|---|---|
| `R(s)` | metered SLOAD of slot `s` of the storage of the precompile whose procedure is running (AccountKeychain in §1, NonceManager in §2, StorageCredits in §4), whoever invoked the procedure |
| `W(s, v)` | metered SSTORE of `v` to slot `s` of that storage (including the TIP-1060 hook from T7, when enabled) |
| `TR(s)`, `TW(s, v)` | metered TLOAD / TSTORE of transient slot `s` |
| `ACC(a)` | metered account-information read of account `a` |
| `DEDUP(n)` | from T11: deduct `20 * n` gas; before T11: no-op (TIP-1105) |
| `LOG(topics, data)` | emit a log from the precompile address (metered as LOG) |
| `ERR(E)` | revert with the ABI-encoded custom error `E` |

Every `R`, `W`, `TR`, `TW` listed is a separate metered operation, even when it touches a slot that
the same call already touched (the second access is warm). An implementation MUST perform exactly
the listed operations in the listed order, because gas, warm sets and the TIP-1060 hook depend on
them. Writes of a value equal to the present value are still performed (`W` of an unchanged value
costs the no-op SSTORE price). Pseudocode in this chapter follows the conventions of
[precompiles/00-framework.md §6.10](00-framework.md#610-pseudocode-conventions); the set procedures of
§0.3 spell out the §6.8 set operations primitive by primitive.

**Warm sets.** Every `R` and `W` follows the warm-set rule of
[precompiles/00-framework.md §3.4](00-framework.md#34-account-warmness), at every fork and whoever
runs the procedure (an ABI call into the precompile, another precompile, or the protocol): it adds
the `(address, slot)` pair and the account that owns the storage (`ACCOUNT_KEYCHAIN_ADDRESS`,
`NONCE_PRECOMPILE_ADDRESS` or `STORAGE_CREDITS_ADDRESS`) to the transaction's EIP-2929 access sets,
and charges only the slot's cold or warm cost, never an account-access cost for that owner. `TR`,
`TW`, `LOG` and `DEDUP` warm nothing; `ACC(a)` warms account `a`. The cross-account paths of this
chapter are: TIP-20 running §1.8 on AccountKeychain storage; SignatureVerifier reading the AccountKeychain
key word (§3.5); the transaction handler running §1.9, §2.4 and §2.5 (§1.9); the StablecoinDEX and
TIP20ChannelReserve reading StorageCredits balances (§4.6.5); and the SSTORE hook reading and writing
StorageCredits balances (§4.4). In each, the touched pairs and the owning account become warm.

Integers are big-endian. `pad32(x)` left-pads a value of at most 32 bytes with zero bytes to 32 bytes
(for an address: 12 zero bytes then the 20 address bytes; for a `bytes4`: 28 zero bytes then the 4
bytes). `u256(b)` interprets 32 bytes as a big-endian integer.

```python
def mapping_slot(key: bytes, base: int) -> int:
    # Tempo mapping slot. Equal to Solidity's keccak256(abi.encode(key, base)) for address,
    # uintN and bytes32 keys; for bytes4 keys the key is LEFT-padded (like a uint32), unlike Solidity.
    return u256(keccak256(pad32(key) + base.to_bytes(32, "big")))

def data_slot(len_slot: int) -> int:
    # start of a dynamic array's elements, as in Solidity
    return u256(keccak256(len_slot.to_bytes(32, "big")))
```

### 0.2 Packed values

A word that packs several fields stores them right-aligned (Solidity convention): the first field
occupies the lowest-order bytes. "Bits a..b" below are counted from the least significant bit of the
256-bit word.

Writing a whole struct that contains a packed slot: before T4 the packed slot is first read and
then written (`R(s); W(s, v)`); from T4 it is only written (`W(s, v)`), with unused bytes zero.
Writing one packed field that shares its slot with another field is always `R(s); W(s, v')`. Writing
a field that is alone in its slot, or is 32 bytes wide, is a single `W`. Reading any field of a slot
is one `R` of that slot.

### 0.3 Enumerable sets

The scope tree uses enumerable sets (OpenZeppelin `EnumerableSet` layout). A set at base slot `b`
occupies two slots:

- `b`: the number of elements `n`.
- `b + 1`: base of a mapping `value -> position`, where position is the 1-based index (0 means
  absent), stored as a full word.
- Elements live at `data_slot(b)` onwards, in insertion order (modified by swap-and-pop removal).
  An `address` element `i` occupies the whole slot `data_slot(b) + i` (value = the address as a
  160-bit integer). A `bytes4` element `i` occupies bits `32*(i % 8) .. 32*(i % 8) + 31` of slot
  `data_slot(b) + i // 8`, holding the 4 bytes as a big-endian 32-bit integer (8 per slot).

The set procedures perform exactly these operations:

```python
def pos(b, v):                      # slot of v's position
    return mapping_slot(v, b + 1)

def read_elem(b, i):                # address: one R; bytes4: one R of the packing slot
    return R(data_slot(b) + i) if ADDRESS else lane(R(data_slot(b) + i // 8), i % 8)

def write_elem(b, i, v):            # address: one W; bytes4: R then W of the packing slot
    if ADDRESS: W(data_slot(b) + i, v)
    else:       s = data_slot(b) + i // 8; W(s, set_lane(R(s), i % 8, v))

def delete_elem(b, i):              # address: W(...,0); bytes4: R then W clearing the lane
    if ADDRESS: W(data_slot(b) + i, 0)
    else:       s = data_slot(b) + i // 8; W(s, set_lane(R(s), i % 8, 0))

def set_contains(b, v):
    return R(pos(b, v)) != 0

def set_is_empty(b):
    return R(b) == 0

def set_read(b):
    n = R(b)
    return [read_elem(b, i) for i in range(n)]

def set_insert(b, v):
    if R(pos(b, v)) != 0:
        return False
    n = R(b)
    W(pos(b, v), n + 1)
    n = R(b)                        # the append re-reads the length
    write_elem(b, n, v)
    W(b, n + 1)
    return True

def set_remove(b, v):               # only used with address sets
    p = R(pos(b, v))
    if p == 0:
        return False
    n = R(b)
    last, idx = n - 1, p - 1
    if idx != last:
        lv = read_elem(b, last)
        W(pos(b, lv), p)
        write_elem(b, idx, lv)
    delete_elem(b, last)
    W(b, last)
    W(pos(b, v), 0)
    return True

def set_delete(b):
    n = R(b)
    for i in range(n):
        v = read_elem(b, i)
        W(pos(b, v), 0)
    n = R(b)
    W(b, 0)
    if ADDRESS:
        for i in range(n): W(data_slot(b) + i, 0)
    else:
        for j in range(ceil(n / 8)): W(data_slot(b) + j, 0)

def set_write(b, values):           # replace contents; only used with address sets of unique values
    old = R(b)
    for i in range(old):
        v = R(data_slot(b) + i)
        W(pos(b, v), 0)
    for i, v in enumerate(values):
        W(pos(b, v), i + 1)
        W(data_slot(b) + i, v)
    W(b, len(values))
    for i in range(len(values), old):
        W(data_slot(b) + i, 0)
```

A stored length or position read above `2^32 - 1` is an out-of-range storage value: an ABI call
reverts with `Panic(0x11)` (precompiles/00-framework.md §5, §6.6, §6.8), and a procedure the protocol
runs (§1.9) fails with that error. No rule in this chapter can store such a value.

## 1. AccountKeychain

The AccountKeychain stores, per account, a set of *access keys*: secondary signing keys that may
sign transactions for the account under an expiry, per-token spending limits (from T3 optionally
periodic) and, from T3, a call-scope allowlist. The account's own key is the *root key*; it is
implicit and never stored. From T6 an access key may be an *admin key*, which may manage other keys.

### 1.1 Constants

| Name | Value |
|---|---|
| `ACCOUNT_KEYCHAIN_ADDRESS` | `0xAAAAAAAA00000000000000000000000000000000` |
| `ZERO_PERIODIC_REMAINING_SENTINEL` | `2^256 - 1` (used from T7) |
| `TIP20_TRANSFER_SELECTOR` | `0xa9059cbb` (`transfer(address,uint256)`) |
| `TIP20_APPROVE_SELECTOR` | `0x095ea7b3` (`approve(address,uint256)`) |
| `TIP20_TRANSFER_WITH_MEMO_SELECTOR` | `0x95777d59` (`transferWithMemo(address,uint256,bytes32)`) |
| `TIP20_PREFIX` | the 12 bytes `0x20C000000000000000000000` |

The three TIP-20 selectors above are the *constrained selectors*. An address *has the TIP-20 prefix*
iff its first 12 bytes equal `TIP20_PREFIX`.

Signature types (the `SignatureType` ABI enum of 4 members, whose canonical ABI type is `uint8`, and
the stored type byte):
`0` Secp256k1, `1` P256, `2` WebAuthn, `3` ConfigurableAccount. Type 3 cannot be stored at T13
or earlier (see [§1.6.1](#161-authorize_key_internal)).

### 1.2 Storage layout

Persistent slots (top-level slot numbers of the AccountKeychain account):

| Slot | Field | Type |
|---|---|---|
| 0 | `keys` | `mapping(address account => mapping(address keyId => AuthorizedKey))` |
| 1 | `spending_limits` | `mapping(bytes32 accountKey => mapping(address token => SpendingLimitState))` |
| 2 | `key_scopes` | `mapping(bytes32 accountKey => KeyScope)` |
| 3 | `key_authorization_witnesses` | `mapping(address account => mapping(bytes32 witness => bool))` |

Transient slots (EIP-1153 storage of the AccountKeychain account; reset at the end of every
transaction):

| Transient slot | Field | Value |
|---|---|---|
| 4 | `transaction_key` | address of the access key that signed the current transaction; `0` = root key |
| 5 | `tx_origin` | the current transaction's sender (recovered signer) |

Both transient values are written only by the protocol (§1.9). Their word is the address as a
160-bit integer.

> **Resolved conflict C-KEY-01**: AccountKeychain.mdx puts `transactionKey` in transient slot 0; the implementation uses transient slot 4 (and slot 5 for `tx_origin`). Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-key-01).

`accountKey` is the account-key row hash:

```python
def account_key(account: Address, key_id: Address) -> bytes32:
    return keccak256(account + key_id)          # 40 bytes: account (20) || keyId (20)
```

Slot derivations:

```python
def key_slot(account, key_id):                  # AuthorizedKey word
    return mapping_slot(key_id, mapping_slot(account, 0))

def limit_slot(account, key_id, token):         # SpendingLimitState base (2 slots)
    return mapping_slot(token, mapping_slot(account_key(account, key_id), 1))

def scope_base(account, key_id):                # KeyScope base (4 slots)
    return mapping_slot(account_key(account, key_id), 2)

def witness_slot(account, witness):
    return mapping_slot(witness, mapping_slot(account, 3))
```

Test vectors, for `account = 0x1111111111111111111111111111111111111111`,
`key_id = 0x2222222222222222222222222222222222222222`, `token = target = 0x20C0000000000000000000000000000000000000`
and `selector = 0xa9059cbb` (each value is a 32-byte slot, hexadecimal):

| Quantity | Value |
|---|---|
| `key_slot(account, key_id)` | `0xd1360c905f62126f789549525bc3219e0fb5feba645fd0705768a3cc3bf3fc5c` |
| `account_key(account, key_id)` | `0xa284ddd69adb56d959922d24c73d2cd9e6b24d5e789a4106eca975c86ec900e1` |
| `limit_slot(account, key_id, token)` (`s0`) | `0xd670f4b1c2069ede83fb68de0e8e7360b44b2757296eefd79ba775b5a480395d` |
| `K = scope_base(account, key_id)` | `0xf9c1141af1c4d8f856a83b1e27e2138a09919ba597e77f8a4d257fc7e4a77f76` |
| `T = mapping_slot(target, K + 3)` (selector set base) | `0xeb8d6e7d50d0a7b96207d35d2771884ea5d07952d91b27756c31b29e51435411` |
| position slot of `selector` in that set, `mapping_slot(pad32(selector), T + 1)` | `0xa006a7c078ca7c9bc253515a4e087a49b74718831d3b082ee29f2fafebbf1dbd` |

#### AuthorizedKey (one word at `key_slot`)

| Bits | Field | Type |
|---|---|---|
| 0..7 | `signature_type` | u8 (0..3) |
| 8..71 | `expiry` | u64 (Unix seconds; `2^64-1` = non-expiring) |
| 72..79 | `enforce_limits` | bool (0 or 1) |
| 80..87 | `is_revoked` | bool |
| 88..95 | `is_admin` | bool (only ever set from T6) |
| 96..255 | unused | 0 |

That is, `word = sig | expiry << 8 | enforce << 72 | revoked << 80 | admin << 88`. A key *exists* iff
`expiry > 0`. A revoked key is stored as `word = 1 << 80` (every other field zero).

#### SpendingLimitState (two words at `s0 = limit_slot(...)` and `s1 = s0 + 1`)

| Slot | Bits | Field | Type |
|---|---|---|---|
| `s0` | 0..255 | `remaining` | u256 |
| `s1` | 0..127 | `max` | u128 |
| `s1` | 128..191 | `period` | u64 (seconds; 0 = one-time limit) |
| `s1` | 192..255 | `period_end` | u64 (Unix seconds) |

Before T3 only `s0` is ever written; rows written before T3 therefore read as `max = period =
period_end = 0`. From T7, a periodic row (`period != 0`) whose remaining allowance is zero stores
`remaining = ZERO_PERIODIC_REMAINING_SENTINEL` instead of 0, and every read of a periodic row decodes
that value as 0 (§1.8). The sentinel cannot collide with a real periodic remaining, which is at most
`2^128 - 1` from T3.

#### KeyScope tree (from T3)

With `K = scope_base(account, key_id)`:

| Slot | Field | Type |
|---|---|---|
| `K + 0` | `is_scoped` | bool (alone in its slot; 1 = the key is call-scoped) |
| `K + 1`, `K + 2` | `targets` | set of `address` (base `K + 1`, §0.3) |
| `K + 3` | `target_scopes` | `mapping(address target => TargetScope)` |

With `T = mapping_slot(target, K + 3)`:

| Slot | Field | Type |
|---|---|---|
| `T + 0`, `T + 1` | `selectors` | set of `bytes4` (base `T`; position keys are `pad32(selector)`, left-padded) |
| `T + 2` | `selector_scopes` | `mapping(bytes4 selector => SelectorScope)`, key left-padded |

With `S = mapping_slot(selector, T + 2)`:

| Slot | Field | Type |
|---|---|---|
| `S + 0`, `S + 1` | `recipients` | set of `address` (base `S`) |

Meaning: `is_scoped = 0` means the key may call anything (the tree is ignored). `is_scoped = 1` with an
empty `targets` set means the key may call nothing. A target in `targets` with an empty `selectors`
set allows every selector (and selector-less calldata) on that target. A selector in `selectors` with
an empty `recipients` set allows every recipient. Child rows exist only for members of the parent
set.

> **Resolved conflict C-KEY-04**: TIP-1011 stores periodic-limit metadata in a separate `spending_limit_period_state` mapping; the implementation extends the `spending_limits` row (`s1`). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-04).

#### Witnesses (from T5)

`key_authorization_witnesses[account][witness]` is 1 once the account burned `witness` through
`burnKeyAuthorizationWitness`, and 0 otherwise. Successful authorizations never write it.

### 1.3 ABI

Struct types (canonical tuple types in brackets):

```solidity
enum SignatureType { Secp256k1, P256, WebAuthn, ConfigurableAccount }          // uint8
struct LegacyTokenLimit { address token; uint256 amount; }                    // (address,uint256)
struct TokenLimit { address token; uint256 amount; uint64 period; }           // (address,uint256,uint64)
struct SelectorRule { bytes4 selector; address[] recipients; }                // (bytes4,address[])
struct CallScope { address target; SelectorRule[] selectorRules; }            // (address,(bytes4,address[])[])
struct KeyRestrictions {                                                      // (uint64,bool,TokenLimit[],bool,CallScope[])
    uint64 expiry; bool enforceLimits; TokenLimit[] limits; bool allowAnyCalls; CallScope[] allowedCalls;
}
struct KeyInfo { SignatureType signatureType; address keyId; uint64 expiry; bool enforceLimits; bool isRevoked; }
```

Functions. "Live" gives the forks at which the selector dispatches; outside that window the selector
is unknown (precompiles/00-framework.md: `UnknownFunctionSelector(bytes4)`). Mutators reject static
calls as the framework specifies.

| Function | Selector | Live | Kind |
|---|---|---|---|
| `authorizeKey(address keyId, SignatureType signatureType, uint64 expiry, bool enforceLimits, (address,uint256)[] limits)` (legacy) | `0x54063a55` | always; from T3 it returns `LegacyAuthorizeKeySelectorChanged` | mutator |
| `authorizeKey(address keyId, SignatureType signatureType, KeyRestrictions config)` | `0x980a6025` | T3+ | mutator |
| `authorizeKey(address keyId, SignatureType signatureType, KeyRestrictions config, bytes32 witness)` | `0xe3c154d2` | T5+ | mutator |
| `authorizeAdminKey(address keyId, SignatureType signatureType, bytes32 witness)` | `0x9a424307` | T6+ (through T13) | mutator |
| `burnKeyAuthorizationWitness(bytes32 witness)` | `0xcff31c46` | T5+ | mutator |
| `revokeKey(address keyId)` | `0x5ae7ab32` | always | mutator |
| `updateSpendingLimit(address keyId, address token, uint256 newLimit)` | `0xcbbb4480` | always | mutator |
| `setAllowedCalls(address keyId, CallScope[] scopes)` | `0xf5456703` | T3+ | mutator |
| `removeAllowedCalls(address keyId, address target)` | `0xf3941811` | T3+ | mutator |
| `getKey(address account, address keyId) returns (KeyInfo)` | `0xbc298553` | always | view |
| `getRemainingLimit(address account, address keyId, address token) returns (uint256)` | `0x63b4290d` | before T3 only | view |
| `getRemainingLimitWithPeriod(address account, address keyId, address token) returns (uint256 remaining, uint64 periodEnd)` | `0xa7f72cab` | T3+ | view |
| `getAllowedCalls(address account, address keyId) returns (bool isScoped, CallScope[] scopes)` | `0x0163e7ec` | T3+ | view |
| `isKeyAuthorizationWitnessBurned(address account, bytes32 witness) returns (bool)` | `0x8e6c7e11` | T5+ | view |
| `isAdminKey(address account, address keyId) returns (bool)` | `0x9009a18d` | T6+ | view |
| `getTransactionKey() returns (address)` | `0xb07fbc1a` | always | view |

`SignatureType` is an enum argument: selectors use its canonical type `uint8`, and it is decoded as an
enum with 4 members under the fork's decoder settings
([precompiles/00-framework.md §4.5](00-framework.md#45-abi-decoder-configuration)); §1.4 gives the
outcome per fork, for all four authorize selectors including the legacy `0x54063a55`.

> **Resolved conflict C-KEY-06**: TIP-1011 specifies a flat 7-argument `authorizeKey` (selector `0x203e2736`) and a `getRemainingLimit` that returns `(uint256, uint64)`; the implementation uses the `KeyRestrictions` tuple form (`0x980a6025`), removes `getRemainingLimit` at T3 and adds `getRemainingLimitWithPeriod`. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-06).

Events (topic0 = keccak256 of the signature; indexed parameters are topics 1..3 in order; the rest
is the ABI-encoded data):

| Event | topic0 |
|---|---|
| `KeyAuthorized(address indexed account, address indexed publicKey, uint8 signatureType, uint64 expiry)` | `0x7c46af0758d3eca5e8195833bff1e5153f6249fc0f2968a878fd28544315a03c` |
| `AdminKeyAuthorized(address indexed account, address indexed publicKey)` | `0x493bc0240c1da6c792754dc5247d39ed76c71c99a43e16777538687f8d05e88e` |
| `KeyRevoked(address indexed account, address indexed publicKey)` | `0x14ce4f0c8c12936436b733974fb13d10fc13e8c41c06dc8e19d82001c93d7989` |
| `SpendingLimitUpdated(address indexed account, address indexed publicKey, address indexed token, uint256 newLimit)` | `0x2ed96330c6ac81a9996d367bd5d4a227c02b9b3ca4c2b077cb943abc6342d00d` |
| `AccessKeySpend(address indexed account, address indexed publicKey, address indexed token, uint256 amount, uint256 remainingLimit)` | `0xe0815e3aaadddf4dd75bde97fc060f0c38afe18e87a169be86a3f5c28247f192` |
| `KeyAuthorizationWitness(address indexed account, bytes32 indexed witness)` | `0x1f09d8956d18ea185372a3f7f40aca24bb45f303920c37c5f0605f4871da41f6` |
| `KeyAuthorizationWitnessBurned(address indexed account, bytes32 indexed witness)` | `0x90c05384a0773712c636a71fde10916abfd2af82c26066b33f082119b47786c2` |

Errors (selector = first 4 bytes of keccak256 of the signature):

| Error | Selector |
|---|---|
| `UnauthorizedCaller()` | `0x5c427cd9` |
| `KeyAlreadyExists()` | `0xaa1ba2f8` |
| `KeyNotFound()` | `0x5f3f479c` |
| `KeyExpired()` | `0x2572e3a9` |
| `SpendingLimitExceeded()` | `0x8a9e71ea` |
| `InvalidSpendingLimit()` | `0x1761dd33` |
| `InvalidSignatureType()` | `0x60cd402d` |
| `ZeroPublicKey()` | `0xb1eddc82` |
| `ExpiryInPast()` | `0x79955a10` |
| `KeyAlreadyRevoked()` | `0xcdf0b34f` |
| `SignatureTypeMismatch(uint8,uint8)` | `0xce699eca` |
| `CallNotAllowed()` | `0x576b38b4` |
| `InvalidCallScope()` | `0x457cabe6` |
| `InvalidKeyId()` | `0xb0aeb53e` |
| `InvalidKeyAuthorizationWitness()` | `0x2dc06cb0` |
| `KeyAuthorizationWitnessAlreadyBurned()` | `0xc96f8deb` |
| `LegacyAuthorizeKeySelectorChanged(bytes4)` | `0x5806c0fd` |

`InvalidKeyAuthorizationWitness` is declared but never raised. `SignatureTypeMismatch(expected,
actual)` carries the stored type and the signature's type.

### 1.4 Dispatch prelude

For every call into the AccountKeychain:

1. Charge the input cost (precompiles/00-framework.md).
2. From T11 (and at T13 and earlier): if the selector is one of the four `authorizeKey` /
   `authorizeAdminKey` selectors (`0x54063a55`, `0x980a6025`,
   `0xe3c154d2`, `0x9a424307`), the calldata is at least 68
   bytes long, and `u256(calldata[36:68]) == 3` (the `signatureType` word is ConfigurableAccount), the
   call MUST revert with empty data. This check runs before selector gating and argument decoding.
3. Dispatch the selector per the table in §1.3 and the framework's decoding rules. Argument decoding
   of the `signatureType` enum: before T11 (permissive decoding) the value is the low-order byte of
   its word, and a byte value of 4 or more decodes to an *invalid* type that later fails with
   `InvalidSignatureType` (§1.6.1); the value 3 decodes to ConfigurableAccount, which also fails with
   `InvalidSignatureType` there. From T11 (strict decoding) a word of 4 or more is a decoding
   failure (empty revert data), and a word of 3 has already reverted with empty data in step 2.
4. Legacy `authorizeKey` (`0x54063a55`): before T3 it behaves as
   `authorize_key(msg.sender, keyId, signatureType, KeyRestrictions{expiry, enforceLimits,
   limits: [(token, amount, period = 0) for each limit], allowAnyCalls: true, allowedCalls: []},
   witness = None)`. From T3, after successful decoding, it MUST revert with
   `LegacyAuthorizeKeySelectorChanged(0x980a6025)` and do nothing else. From T11 a legacy call whose
   `signatureType` word is 3 or more therefore reverts with empty data (step 2 or a decoding failure),
   not with `LegacyAuthorizeKeySelectorChanged`.

> **Resolved conflict C-KEY-02**: AccountKeychain.mdx says an unsupported `signatureType` reverts with `InvalidSignatureType`; from T11 the implementation reverts with empty data for 3 and for values of 4 or more. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-key-02).

### 1.5 Common procedures

`now` is `header.timestamp` (seconds), saturated to `u64`. `msg.sender` is the immediate caller of
the precompile.

```python
def read_key(account, key_id) -> AuthorizedKey:
    return decode_key(R(key_slot(account, key_id)))

def write_key(account, key_id, key: AuthorizedKey):
    s = key_slot(account, key_id)
    if not T4: R(s)                          # pre-T4 struct write reads the packed slot first
    W(s, encode_key(key))

def load_active_key(account, key_id) -> AuthorizedKey:
    key = read_key(account, key_id)          # one R
    if key.is_revoked:      raise ERR(KeyAlreadyRevoked)
    if key.expiry == 0:     raise ERR(KeyNotFound)
    if now >= key.expiry:   raise ERR(KeyExpired)
    return key

def is_admin_key(account, key_id) -> bool:
    if key_id == account:
        return True                          # the root key is implicitly admin; no storage read
    try:
        return load_active_key(account, key_id).is_admin
    except KeychainError:                    # KeyAlreadyRevoked / KeyNotFound / KeyExpired
        return False

def ensure_admin_caller(msg_sender):
    tk = TR(4)                               # transaction_key
    if tk != 0:
        if not T6 or not is_admin_key(msg_sender, tk):
            raise ERR(UnauthorizedCaller)
    if T2:
        origin = TR(5)                       # tx_origin
        if origin == 0 or origin != msg_sender:
            raise ERR(UnauthorizedCaller)
```

`ensure_admin_caller` therefore admits: the root key (no access key signed the transaction); from T6
also an active admin access key of `msg.sender`; and from T2 only when `msg.sender` is the
transaction sender itself (a contract called within a root-signed transaction cannot manage its own
keys from T2, but could before T2). Errors that are not keychain business errors (storage or
out-of-gas failures) propagate unchanged from every procedure in this chapter.

#### Spending-limit row helpers

```python
def read_limit(account, key_id, token) -> SpendingLimitState:     # R(s0), R(s1)
    s0 = limit_slot(account, key_id, token)
    return SpendingLimitState(remaining=R(s0), **unpack_s1(R(s0 + 1)))

def write_limit(account, key_id, token, st):                      # W(s0), [R(s1)], W(s1)
    s0 = limit_slot(account, key_id, token)
    W(s0, st.remaining)
    if not T4: R(s0 + 1)
    W(s0 + 1, st.max | st.period << 128 | st.period_end << 192)

def write_remaining(account, key_id, token, v):                   # W(s0)
    W(limit_slot(account, key_id, token), v)

def t3_cap(amount) -> int:                                        # from T3
    if amount > 2**128 - 1: raise ERR(InvalidSpendingLimit)
    return amount
```

### 1.6 Mutators

#### 1.6.1 authorize_key_internal

All key-creating entry points (the three `authorizeKey` selectors, `authorizeAdminKey`, and the
protocol's processing of a transaction's `key_authorization`, §1.9.3) run this procedure with
`account = msg_sender`:

```python
def authorize_key_internal(msg_sender, key_id, sig_type, cfg: KeyRestrictions, witness, is_admin):
    ensure_admin_caller(msg_sender)
    if key_id == 0:
        raise ERR(ZeroPublicKey)
    if is_admin and key_id == msg_sender:
        raise ERR(InvalidKeyId)
    if T0 and cfg.expiry <= now:                       # T0+: always on mainnet
        raise ERR(ExpiryInPast)
    existing = read_key(msg_sender, key_id)            # R(key_slot)
    if existing.expiry > 0:
        raise ERR(KeyAlreadyExists)
    if existing.is_revoked:
        raise ERR(KeyAlreadyRevoked)
    if sig_type not in (0, 1, 2):                      # 3 (ConfigurableAccount) and invalid values
        raise ERR(InvalidSignatureType)
    if T3:
        if cfg.enforceLimits and has_duplicate_tokens(cfg.limits):   # in-memory, no gas
            raise ERR(InvalidSpendingLimit)
        if cfg.allowAnyCalls:
            if T5 and len(cfg.allowedCalls) > 0:
                raise ERR(InvalidCallScope)
            allowed = None                             # T3/T4: allowedCalls silently ignored
        else:
            allowed = cfg.allowedCalls                 # may be [] (scoped deny-all)
    else:
        if any(l.period != 0 for l in cfg.limits):     # checked even if enforceLimits is false
            raise ERR(InvalidSpendingLimit)
        if not cfg.allowAnyCalls or len(cfg.allowedCalls) > 0:
            raise ERR(InvalidCallScope)
        allowed = None
    if witness is not None and R(witness_slot(msg_sender, witness)) != 0:
        raise ERR(KeyAuthorizationWitnessAlreadyBurned)

    write_key(msg_sender, key_id, AuthorizedKey(
        signature_type=sig_type, expiry=cfg.expiry, enforce_limits=cfg.enforceLimits,
        is_revoked=False, is_admin=is_admin))

    if not is_admin:
        limits = cfg.limits if cfg.enforceLimits else []
        for l in limits:                               # input order
            if T3:
                write_limit(msg_sender, key_id, l.token, SpendingLimitState(
                    remaining=l.amount, max=t3_cap(l.amount), period=l.period,
                    period_end=0 if l.period == 0 else saturating_add(now, l.period)))
            else:
                write_remaining(msg_sender, key_id, l.token, l.amount)   # duplicates: last wins
        if T3:
            replace_allowed_calls(account_key(msg_sender, key_id), allowed)   # §1.6.7

    if witness is not None:
        LOG([KeyAuthorizationWitness, msg_sender, witness], b"")
    LOG([KeyAuthorized, msg_sender, key_id], abi_encode(uint8(sig_type), uint64(cfg.expiry)))
```

Notes:

- `t3_cap` is evaluated when each limit is written, so an over-large amount fails after the key word
  and earlier limits were written (the whole call then reverts).
- When `enforceLimits` is false, limits are neither written nor checked for duplicates or size
  (before T3 the `period` check above still applies).
- Before T3, duplicate tokens are accepted and the last one wins.
- From T3, duplicate tokens are rejected only when `enforceLimits` is true. A transaction's
  `key_authorization` sets `enforceLimits` exactly when it carries limits (§1.9.3), so for it every
  duplicate is rejected; an ABI call with `enforceLimits = false` and duplicate tokens succeeds.
- An admin key (`is_admin`) writes only the key word: no limit rows and no scope tree (so its
  `is_scoped` slot stays 0).

> **Resolved conflict C-KEY-13**: TIP-1011 (TokenLimit rule 4) requires duplicate token entries in an authorization to be rejected unconditionally; the implementation checks for duplicates only when `enforceLimits` is true, and ignores the limits otherwise. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-13).

> **Resolved conflict C-KEY-03**: AccountKeychain.mdx says recipient-constrained selector rules are validated before any state is written; the implementation writes the key word (and the scope-tree reset) before validating scopes, and before T4 validates each scope while inserting it. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-key-03).

#### 1.6.2 authorizeKey (T3 `0x980a6025`, T5 `0xe3c154d2`)

`authorize_key_internal(msg.sender, keyId, signatureType, config, witness, is_admin=False)`, where
`witness` is `None` for the T3 selector and the `bytes32` argument for the T5 selector
(`bytes32(0)` is a valid witness that is checked and emitted like any other). Returns nothing.

#### 1.6.3 authorizeAdminKey (`0x9a424307`, T6+)

```python
authorize_key_internal(msg.sender, keyId, signatureType,
    KeyRestrictions(expiry=2**64 - 1, enforceLimits=False, limits=[], allowAnyCalls=True, allowedCalls=[]),
    witness=witness, is_admin=True)
LOG([AdminKeyAuthorized, msg.sender, keyId], b"")
```

The ABI path always passes a witness. Event order for an admin key: `KeyAuthorizationWitness`,
`KeyAuthorized`, `AdminKeyAuthorized`.

#### 1.6.4 burnKeyAuthorizationWitness (`0xcff31c46`, T5+)

```python
ensure_admin_caller(msg.sender)
s = witness_slot(msg.sender, witness)
if R(s) != 0:
    raise ERR(KeyAuthorizationWitnessAlreadyBurned)
W(s, 1)
LOG([KeyAuthorizationWitnessBurned, msg.sender, witness], b"")
```

From T6 an admin access key passes `ensure_admin_caller` and may therefore burn witnesses.

> **Resolved conflict C-KEY-07**: TIP-1053 says access keys MUST NOT burn witnesses; from T6 the implementation lets an admin access key burn them (as do the docs). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-07).

#### 1.6.5 revokeKey (`0x5ae7ab32`)

```python
ensure_admin_caller(msg.sender)
key = read_key(msg.sender, keyId)                 # R
if key.expiry == 0:                               # missing or already revoked
    raise ERR(KeyNotFound)
write_key(msg.sender, keyId, AuthorizedKey(is_revoked=True))   # word = 1 << 80
LOG([KeyRevoked, msg.sender, keyId], b"")
```

Revocation does not check expiry or the admin flag (an expired key, an admin key, or the signing admin
key itself can be revoked). Spending-limit rows and the scope tree are left in storage; every reader
treats them as unreachable because the key word is revoked. A revoked key id can never be
authorized again for the same account.

#### 1.6.6 updateSpendingLimit (`0xcbbb4480`)

```python
ensure_admin_caller(msg.sender)
key = load_active_key(msg.sender, keyId)          # R; KeyAlreadyRevoked / KeyNotFound / KeyExpired
if key.is_admin:
    raise ERR(InvalidKeyId)
if not key.enforce_limits:
    key.enforce_limits = True
    write_key(msg.sender, keyId, key)             # an unlimited key becomes limited
if T3:
    st = read_limit(msg.sender, keyId, token)     # R(s0), R(s1)
    st.remaining = newLimit
    st.max = t3_cap(newLimit)                     # period and period_end are preserved
    write_limit(msg.sender, keyId, token, st)
else:
    write_remaining(msg.sender, keyId, token, newLimit)
LOG([SpendingLimitUpdated, msg.sender, keyId, token], abi_encode(uint256(newLimit)))
```

Updating a token that had no row creates a one-time limit (`period = 0`). Before T3 any `uint256`
is accepted.

#### 1.6.7 Call-scope storage procedures (T3+)

With `K = scope_base(account, key_id)` (passed around as the row hash `h = account_key(...)`, from
which `K = mapping_slot(h, 2)`), `targets_b = K + 1`, `T(t) = mapping_slot(t, K + 3)`, selector set
base `T(t)`, `S(t, sel) = mapping_slot(sel, T(t) + 2)`, recipient set base `S(t, sel)`:

```python
def replace_allowed_calls(h, allowed):        # used only by authorize_key_internal
    clear_all_target_scopes(h)
    if allowed is None:
        W(K + 0, 0)                           # is_scoped = false
        return
    W(K + 0, 1)                               # is_scoped = true
    if len(allowed) == 0:
        return                                # scoped deny-all
    validate_call_scopes(allowed)
    for scope in allowed:
        upsert_target_scope(h, scope)

def clear_all_target_scopes(h):
    for t in set_read(targets_b):
        clear_target_selectors(h, t)
    set_delete(targets_b)

def clear_target_selectors(h, t):
    for sel in set_read(T(t)):                # bytes4 set
        set_delete(S(t, sel))                 # recipients (address set)
    set_delete(T(t))

def remove_target_scope(h, t):
    if not set_remove(targets_b, t):
        return
    clear_target_selectors(h, t)

def upsert_target_scope(h, scope):
    if not T4:
        validate_call_scope(scope)            # pre-T4: validated inline, scope by scope
    set_insert(targets_b, scope.target)
    clear_target_selectors(h, scope.target)
    if len(scope.selectorRules) == 0:
        return                                # any selector allowed on this target
    for rule in scope.selectorRules:
        set_insert(T(scope.target), rule.selector)
        if len(rule.recipients) == 0:
            if not T4:
                set_delete(S(scope.target, rule.selector))   # pre-T4 only: delete of the empty set
        else:
            set_write(S(scope.target, rule.selector), rule.recipients)

def validate_call_scopes(scopes):
    if T11:
        DEDUP(len(scopes))
        if has_duplicates([s.target for s in scopes]): raise ERR(InvalidCallScope)
        for s in scopes: validate_call_scope(s)
        return
    seen = set()
    for s in scopes:                          # pre-T11: per scope, duplicate check then (T4+) validation
        if s.target in seen: raise ERR(InvalidCallScope)
        seen.add(s.target)
        if T4: validate_call_scope(s)

def validate_call_scope(scope):
    if scope.target == 0: raise ERR(InvalidCallScope)
    if len(scope.selectorRules) > 0:
        validate_selector_rules(scope.target, scope.selectorRules)

def validate_selector_rules(target, rules):
    is_tip20 = None                           # evaluated at most once per call of this procedure
    if T11:
        DEDUP(len(rules))
        if has_duplicates([r.selector for r in rules]): raise ERR(InvalidCallScope)
    seen = set()
    for r in rules:
        if not T11:
            if r.selector in seen: raise ERR(InvalidCallScope)
            seen.add(r.selector)
        if len(r.recipients) == 0:
            continue
        if r.selector not in CONSTRAINED_SELECTORS:
            raise ERR(InvalidCallScope)       # is_tip20 not evaluated
        if is_tip20 is None:
            if T4: is_tip20 = has_tip20_prefix(target)                     # no state access
            else:  is_tip20 = has_tip20_prefix(target) and code_nonempty(ACC(target))
                                              # pre-T4: ACC only if the prefix matches
        if not is_tip20: raise ERR(InvalidCallScope)
        if any(x == 0 for x in r.recipients): raise ERR(InvalidCallScope)
        DEDUP(len(r.recipients))              # only reached if no recipient is zero
        if has_duplicates(r.recipients): raise ERR(InvalidCallScope)
```

Consequences an implementation MUST reproduce:

- Every authorization of a non-admin key from T3, even an unrestricted one, first runs
  `clear_all_target_scopes` on the (normally empty) tree, i.e. at least `R(K+1)` three times and
  `W(K+1, 0)`, then writes `is_scoped`.
- `upsert_target_scope` always clears the target's previous selector and recipient rows and then
  re-inserts them, so `setAllowedCalls` fully replaces each named target's subtree.
- Before T4, validation errors surface after earlier scopes (and the current scope's preceding
  storage operations) were already processed; from T4, all scopes are validated before the first
  `upsert_target_scope`. Selector order within a scope and recipient order within a rule are kept as
  given.

#### 1.6.8 setAllowedCalls (`0xf5456703`, T3+)

```python
ensure_admin_caller(msg.sender)
key = load_active_key(msg.sender, keyId)
if key.is_admin: raise ERR(InvalidKeyId)
if len(scopes) == 0: raise ERR(InvalidCallScope)
h = account_key(msg.sender, keyId)
K = scope_base(msg.sender, keyId)
validate_call_scopes(scopes)
for scope in scopes:
    upsert_target_scope(h, scope)
W(K + 0, 1)                                    # is_scoped = true (after the upserts)
```

Targets not named in `scopes` keep their existing subtrees. Calling it on an unrestricted key turns
the key into a scoped key whose allowlist is exactly the named targets (plus any rows left from
earlier scoped periods). No event is emitted.

#### 1.6.9 removeAllowedCalls (`0xf3941811`, T3+)

```python
ensure_admin_caller(msg.sender)
key = load_active_key(msg.sender, keyId)
if key.is_admin: raise ERR(InvalidKeyId)
K = scope_base(msg.sender, keyId)
if R(K + 0) == 0:                              # unrestricted key: no-op
    return
remove_target_scope(account_key(msg.sender, keyId), target)
```

Removing an absent target is a no-op. Removing the last target leaves the key scoped with no targets
(deny-all). No event is emitted.

> **Resolved conflict C-KEY-05**: TIP-1011 says `removeAllowedCalls` only disables the target scope and that prior selector rows may remain in state; the implementation removes the target from the set and deletes every selector and recipient row under it. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-05).

### 1.7 Views

All views perform only reads and never write.

```python
def getKey(account, keyId) -> KeyInfo:
    key = read_key(account, keyId)                                   # R
    if key.expiry == 0 or key.is_revoked:
        return KeyInfo(signatureType=0, keyId=0, expiry=0, enforceLimits=False, isRevoked=key.is_revoked)
    return KeyInfo(key.signature_type, keyId, key.expiry, key.enforce_limits, key.is_revoked)
    # an expired key is reported with its stored fields; is_admin is not reported

def getRemainingLimit(account, keyId, token) -> uint256:            # before T3 only
    if not T2:
        return R(limit_slot(account, keyId, token))                  # raw stored remaining
    return effective_limit_state(account, keyId, token)[0]

def getRemainingLimitWithPeriod(account, keyId, token) -> (uint256, uint64):   # T3+
    return effective_limit_state(account, keyId, token)

def effective_limit_state(account, key_id, token):
    if key_id == 0 and T3:
        return (0, 0)                                                # no reads
    key = read_key(account, key_id)                                  # R
    if key.is_revoked or key.expiry == 0:
        return (0, 0)
    if T3 and now >= key.expiry:
        return (0, 0)
    s0 = limit_slot(account, key_id, token)
    remaining = R(s0)
    if not T3:
        return (remaining, 0)
    period = period_of(R(s0 + 1))
    if period == 0:
        return (remaining, 0)
    if T7 and remaining == ZERO_PERIODIC_REMAINING_SENTINEL:
        remaining = 0
    period_end = period_end_of(R(s0 + 1))
    if now < period_end:
        return (remaining, period_end)
    nxt = next_period_end(period_end, period, now)
    return (max_of(R(s0 + 1)), nxt)                                  # rolled over (not persisted)
```

`effective_limit_state` does not consult `enforce_limits`; for an unlimited key it reports the
stored row (normally zero). Note the separate `R(s0 + 1)` for each of `period`, `period_end` and
`max`.

```python
def getAllowedCalls(account, keyId) -> (bool, CallScope[]):          # T3+
    if keyId == 0:
        return (False, [])                                           # no reads
    key = read_key(account, keyId)                                   # R
    if key.expiry == 0 or key.is_revoked or now >= key.expiry:
        return (True, [])                                            # missing/revoked/expired: deny-all
    K = scope_base(account, keyId)
    if R(K + 0) == 0:
        return (False, [])
    scopes = []
    for t in set_read(K + 1):                                        # storage order
        sels = set_read(T(t))
        if len(sels) == 0:
            scopes.append(CallScope(t, []))
            continue
        rules = [SelectorRule(sel, set_read(S(t, sel))) for sel in sels]
        scopes.append(CallScope(t, rules))
    return (True, scopes)

def isKeyAuthorizationWitnessBurned(account, witness) -> bool:      # T5+
    return R(witness_slot(account, witness)) != 0

def isAdminKey(account, keyId) -> bool:                              # T6+
    return is_admin_key(account, keyId)

def getTransactionKey() -> address:
    return TR(4)                                                     # 0 means the root key
```

`getAllowedCalls` returns targets, selectors and recipients in their stored set order (insertion
order as modified by swap-and-pop removal).

### 1.8 Spending limits

Spending limits restrict how much of each TIP-20 token an access key may move per transaction
lifetime (one-time) or per period (periodic, T3+). They are enforced only for keys with
`enforce_limits = true` and only for the transaction's own access key, through the internal entry
points below. Which TIP-20 operations call them is specified in precompiles/tip20.md (direct
transfers and approvals by the transaction sender, fee collection, and from T12 `burnAt`); the fee
refund path is in §1.8.3.

```python
def next_period_end(period_end, period, now) -> u64:   # all arithmetic saturates at 2**64 - 1
    elapsed = saturating_sub(now, period_end)
    periods = saturating_add(elapsed // period, 1)
    return saturating_add(period_end, saturating_mul(period, periods))
```

#### 1.8.1 verify_and_update_spending

```python
def verify_and_update_spending(account, key_id, token, amount):
    if key_id == 0:
        return
    key = load_active_key(account, key_id)            # R; KeyAlreadyRevoked / KeyNotFound / KeyExpired
    if not key.enforce_limits:
        return
    if not T3:
        s0 = limit_slot(account, key_id, token)
        remaining = R(s0)
        if amount > remaining: raise ERR(SpendingLimitExceeded)
        W(s0, remaining - amount)                     # no event before T3
        return
    st = read_limit(account, key_id, token)           # R(s0), R(s1)
    remaining = st.remaining
    periodic = st.period != 0
    if periodic:
        if T7 and remaining == ZERO_PERIODIC_REMAINING_SENTINEL:
            remaining = 0
        if now >= st.period_end:
            st.period_end = next_period_end(st.period_end, st.period, now)
            remaining = st.max
            st.remaining = st.max
    if amount > remaining:
        raise ERR(SpendingLimitExceeded)              # a rollover is not persisted on failure
    new_remaining = remaining - amount
    if periodic:
        st.remaining = ZERO_PERIODIC_REMAINING_SENTINEL if (T7 and new_remaining == 0) else new_remaining
        write_limit(account, key_id, token, st)       # W(s0), [R(s1) pre-T4], W(s1)
    else:
        W(limit_slot(account, key_id, token), new_remaining)
    LOG([AccessKeySpend, account, key_id, token], abi_encode(uint256(amount), uint256(new_remaining)))
```

`AccessKeySpend.remainingLimit` is the decoded value (0, never the sentinel). A token with no row has
`remaining = 0`, so any nonzero spend of it by a limited key fails. A zero-amount spend still performs
the writes and emits the event.

#### 1.8.2 authorize_transfer and authorize_approve

```python
def authorize_transfer(account, token, amount):
    tk = TR(4)
    if tk == 0: return                                # root key: no limits
    if account != TR(5): return                       # only the transaction sender's own spends count
    verify_and_update_spending(account, tk, token, amount)

def authorize_approve(account, token, old_allowance, new_allowance):
    tk = TR(4)
    if tk == 0: return
    if account != TR(5): return
    increase = saturating_sub(new_allowance, old_allowance)
    if increase == 0: return                          # lowering or keeping an allowance is free
    verify_and_update_spending(account, tk, token, increase)
```

#### 1.8.3 refund_spending_limit (fee refund, T1C+)

Called by the fee token's post-transaction refund (precompiles/tip20.md, `transfer_fee_post_tx`)
from T1C with the refunded amount:

```python
def refund_spending_limit(account, token, amount):
    tk = TR(4)
    if tk == 0: return
    if account != TR(5): return
    try:
        key = load_active_key(account, tk)
    except KeychainError:
        return                                        # revoked/expired/missing: nothing restored
    if not key.enforce_limits: return
    if not T3:
        s0 = limit_slot(account, tk, token)
        W(s0, saturating_add(R(s0), amount))
        return
    st = read_limit(account, tk, token)               # R(s0), R(s1)
    if T7 and st.period != 0 and st.remaining == ZERO_PERIODIC_REMAINING_SENTINEL:
        refunded = amount
    else:
        refunded = saturating_add(st.remaining, amount)
    st.remaining = refunded if st.max == 0 else min(refunded, st.max)   # max == 0: legacy row, unclamped
    write_limit(account, tk, token, st)               # no rollover, no event
```

#### 1.8.4 Periodic-limit invariants

From T3: `max <= 2^128 - 1`; a periodic row's decoded `remaining <= max` after any operation
except on rows written before T3; `period_end` only moves forward, and after a rollover
`period_end > now` unless saturated at `2^64 - 1`. From T7 a periodic row never stores
`remaining = 0` as a result of a spend: this keeps the `s0` slot nonzero so that exhausting a
periodic limit cannot mint a storage credit (§4) that a later, accounting-free fee pre-collection
would leave unbacked. (A periodic row whose configured amount is 0 still stores 0.)

### 1.9 Internal interface used by the transaction handler

The handler (06-transactions-and-fees.md) calls the following AccountKeychain procedures directly,
not through ABI dispatch: they are native host invocations
([precompiles/00-framework.md §9.1](00-framework.md#91-native-host-invocations)). Unless
06-transactions-and-fees.md says otherwise they run with TIP-1060 accounting disabled (§4.6) and their
gas is covered by the transaction's intrinsic gas; the exceptions are the T1/T1A key-authorization
write (§1.9.3) and, from T3, call-scope prevalidation (§1.9.4), which are metered. Their storage
effects and logs are as specified here. An error raised by any of them makes the transaction invalid
unless 06-transactions-and-fees.md maps it otherwise.

**Warmth from protocol invocations.** Metered or not, at every fork (including the T1/T1A metered
key-authorization path), these invocations warm what they touch as §0.1 states, and the warmth
persists into the EVM phase of the same transaction
([precompiles/00-framework.md §3.4](00-framework.md#34-account-warmness)): the access key's
`key_slot` read by key validation (§1.9.2); every slot read or written by a key authorization
(§1.9.3) and by the fee spending-limit deduction (`authorize_transfer`, §1.8.2); the nonce slot of
`increment_nonce` (§2.4); the seen, ring and pointer slots of `check_and_mark_expiring_nonce` (§2.5);
and in each case the owning account (`ACCOUNT_KEYCHAIN_ADDRESS` or `NONCE_PRECOMPILE_ADDRESS`). The
transient writes `set_tx_origin` and `set_transaction_key` (§1.9.1) warm nothing. Consequences: in a
transaction signed by access key `k` of `account`, a later `verifyKeychain` of a signature by `k`
pays 100 for its read of `key_slot(account, k)`, an EVM call to `ACCOUNT_KEYCHAIN_ADDRESS` pays the
warm account-access cost (100), and in a 2D-nonce transaction a `getNonce(sender, nonce_key)` call
pays 100 for its read and 100 for the call to `NONCE_PRECOMPILE_ADDRESS`.

#### 1.9.1 Transient context

- `set_tx_origin(origin)`: `TW(5, origin)`. Called for every transaction before fee resolution,
  with the transaction's recovered sender.
- `set_transaction_key(key_id)`: `TW(4, key_id)`. Called for a keychain-signed transaction once its
  access key has been validated (existing key), or, when the transaction's `key_authorization`
  registers the same key that signs it, right after that authorization is applied. A root-signed
  transaction leaves slot 4 at 0. A T6 transaction whose `key_authorization` is signed by an admin
  access key keeps that admin key as the transaction key.

Both slots are transient, so they return to 0 at the end of every transaction.

#### 1.9.2 validate_keychain_authorization

```python
def validate_keychain_authorization(account, key_id, now, expected_sig_type):
    key = load_active_key(account, key_id)            # R
    if expected_sig_type is not None and key.signature_type != expected_sig_type:
        raise ERR(SignatureTypeMismatch(key.signature_type, expected_sig_type))
    return key
```

The handler passes the inner signature's type from T1 (and also before T1 when the transaction
carries a `key_authorization`), and `None` otherwise; SignatureVerifier passes `None` (§3).

#### 1.9.3 Key authorization from a transaction

For a transaction's `key_authorization` (02-encoding.md, 06-transactions-and-fees.md), the protocol
calls, with `msg_sender` = the transaction sender:

- if the authorization is an admin authorization (T6 `is_admin`): `authorize_key_internal(sender,
  key_id, key_type, <admin restrictions as in §1.6.3>, witness, is_admin=True)` followed by the
  `AdminKeyAuthorized` log; `witness` is the authorization's optional witness (absent → `None`: no
  burn check and no witness event);
- otherwise `authorize_key_internal(sender, key_id, key_type, cfg, witness, is_admin=False)` with
  `cfg.expiry = expiry if present else 2^64 - 1`, `cfg.enforceLimits = (limits present)`,
  `cfg.limits = [(token, limit, period)]` (period 0 when absent), `cfg.allowAnyCalls =
  (allowed_calls absent)`, `cfg.allowedCalls = allowed_calls or []`.

`ensure_admin_caller` inside it sees `tx_origin = sender` and the transaction key as set at that
point (0 for a root-signed or same-key authorization, the admin key for a T6 admin-signed one).

At T1 and T1A (not before T1, and not from T1B) this invocation is metered under the
[T1/T1A metered gas table](00-framework.md#911-t1t1a-metered-gas-table), with the gas limit and
out-of-gas rollback of 06-transactions-and-fees.md §4.10.2; at every other fork its gas is part of
intrinsic gas and its primitives cost the transaction nothing.

Worked example (T1, root-signed transaction): a `key_authorization` for a new secp256k1 key with an
expiry and limits `[(tokenA, 1000), (tokenB, 5000)]` (distinct tokens, nonzero amounts, no witness,
which T1 does not support). The pre-T3 path of §1.6.1 performs, in order:

| Step | Primitive | T1/T1A gas |
|---|---|---|
| `ensure_admin_caller`: transaction key (no `tx_origin` read before T2) | `TR(4)` | 100 |
| existing-key check | `R(key_slot)` | 100 |
| `write_key`, pre-T4 whole-struct write | `R(key_slot)`; `W(key_slot, word)`, zero → nonzero | 100 + 250,000 |
| limit for `tokenA` (`remaining` only, a full word, no load) | `W(s0_A, 1000)`, zero → nonzero | 250,000 |
| limit for `tokenB` | `W(s0_B, 5000)`, zero → nonzero | 250,000 |
| `KeyAuthorized` (3 topics, 64 data bytes; emitted at T1) | `LOG` | 375 |
| **Total** | | **750,675** |

A limit with amount 0 would be a zero → zero write costing 0. `set_transaction_key` is not part of
this invocation.

#### 1.9.4 validate_call_scope_for_transaction (T3+)

Called for each top-level call of an access-key-signed transaction before the first call executes,
under metered gas (06-transactions-and-fees.md):

```python
def validate_call_scope_for_transaction(account, key_id, to, input):
    if key_id == 0 or not T3:
        return
    if to is CREATE:
        raise ERR(CallNotAllowed)                      # no reads
    K = scope_base(account, key_id)
    if R(K + 0) == 0:
        return                                         # unrestricted
    if not set_contains(K + 1, to):
        raise ERR(CallNotAllowed)
    if set_is_empty(T(to)):
        return                                         # any selector, including calldata < 4 bytes
    if len(input) < 4:
        raise ERR(CallNotAllowed)
    sel = input[0:4]
    if not set_contains(T(to), sel):
        raise ERR(CallNotAllowed)
    if set_is_empty(S(to, sel)):
        return                                         # any recipient
    if len(input) < 36:
        raise ERR(CallNotAllowed)
    word = input[4:36]
    if word[0:12] != bytes(12):
        raise ERR(CallNotAllowed)                      # non-canonical address argument
    if not set_contains(S(to, sel), word[12:32]):
        raise ERR(CallNotAllowed)
```

This procedure does not re-check the key's expiry or revocation (the handler validated the key).
Its `CREATE` branch is unreachable for a transaction that passed the structure checks of
06-transactions-and-fees.md §4.2: a `CREATE` other than the first call is invalid at every fork, and
from T3 a first-call `CREATE` in a Keychain-signed transaction is invalid. Both outcomes are
transaction invalidity, as TIP-1011 requires.

#### 1.9.5 Other callers

`authorize_transfer`, `authorize_approve` and `refund_spending_limit` (§1.8) are called from the
TIP-20 precompile; `verify_and_update_spending` is reached only through them. Their `TR`, `R` and `W`
are metered in the calling TIP-20 storage context and act on AccountKeychain storage: each `R`/`W`
warms its AccountKeychain slot and `ACCOUNT_KEYCHAIN_ADDRESS` and charges no account-access cost
(§0.1).

### 1.10 Log order

Logs emitted by one AccountKeychain operation, in order:

| Operation | Logs |
|---|---|
| authorize (non-admin) | `KeyAuthorizationWitness` (only with a witness), `KeyAuthorized` |
| authorize admin | `KeyAuthorizationWitness` (only with a witness), `KeyAuthorized`, `AdminKeyAuthorized` |
| burnKeyAuthorizationWitness | `KeyAuthorizationWitnessBurned` |
| revokeKey | `KeyRevoked` |
| updateSpendingLimit | `SpendingLimitUpdated` |
| spend (verify_and_update_spending) | `AccessKeySpend` from T3; nothing before T3 |
| setAllowedCalls, removeAllowedCalls, refund_spending_limit | none |

A protocol-applied key authorization emits its logs into the transaction's log list before any call
of the transaction executes; whether they survive a failing call batch is specified in
05-block-execution.md and 06-transactions-and-fees.md.

## 2. NonceManager

The NonceManager holds 2D nonce sequences (nonce keys other than 0) and the expiring-nonce replay
set. The protocol nonce (nonce key 0) is the ordinary account nonce in the state trie and is not
stored here.

### 2.1 Constants

| Name | Value |
|---|---|
| `NONCE_PRECOMPILE_ADDRESS` | `0x4E4F4E4345000000000000000000000000000000` |
| `TEMPO_EXPIRING_NONCE_KEY` | `2^256 - 1` |
| `EXPIRING_NONCE_SET_CAPACITY` | 300,000 before T11; 3,000,000 from T11 |
| `EXPIRING_NONCE_MAX_EXPIRY_SECS` | 30 before T11; 300 from T11 |

Both expiring-nonce parameters are selected by the fork active for the block being executed.

### 2.2 Storage layout

| Slot | Field | Type |
|---|---|---|
| 0 | `nonces` | `mapping(address account => mapping(uint256 nonceKey => uint64))` |
| 1 | `expiring_nonce_seen` | `mapping(bytes32 replayHash => uint64 validBefore)` |
| 2 | `expiring_nonce_ring` | `mapping(uint32 index => bytes32 replayHash)` |
| 3 | `expiring_nonce_ring_ptr` | `uint32` (alone in the slot) |

```python
def nonce_slot(account, nonce_key):            # = keccak256(abi.encode(nonceKey, keccak256(abi.encode(account, 0))))
    return mapping_slot(nonce_key.to_bytes(32, "big"), mapping_slot(account, 0))
def seen_slot(h):  return mapping_slot(h, 1)
def ring_slot(i):  return mapping_slot(i.to_bytes(4, "big"), 2)   # uint32 key, left-padded
PTR_SLOT = 3
```

Test vectors: `ring_slot(0) = 0xac33ff75c19e70fe83507db0d683fd3465c996598dc972688b7ace676c89077b`;
`nonce_slot(0x1111111111111111111111111111111111111111, 1) =
0x5e1e8d7a153ea63f1dff93fab2c49e87ac787007f54fbf1809a4dee6a9bff898`.

All values are stored as full words (`uint64`/`uint32` right-aligned). The ring pointer is always in
`[0, EXPIRING_NONCE_SET_CAPACITY)` for the capacity in force when it was written.

> **Resolved conflict C-KEY-10**: spec-tempo-transaction.mdx gives the 2D nonce storage key as `keccak256(abi.encode(account_address, nonce_key))`; the implementation uses the nested mapping at slot 0 above. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-key-10).

### 2.3 ABI

| Item | Selector / topic0 |
|---|---|
| `getNonce(address account, uint256 nonceKey) returns (uint64 nonce)` (view) | `0x89535803` |
| `event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce)` | `0x42d98041765078b1557c6a9fe7e4a27230ca413fc141df57d89acd6cc68ffb45` |
| `error ProtocolNonceNotSupported()` | `0x1bc81ca9` |
| `error InvalidNonceKey()` | `0xdf9b1c41` |
| `error NonceOverflow()` | `0xadc15572` |
| `error ExpiringNonceReplay()` | `0x4ba8e2af` |
| `error ExpiringNonceSetFull()` | `0x4adf682a` |
| `error InvalidExpiringNonceExpiry()` | `0xd54ed552` |

`getNonce` is the only ABI function (all forks). After the input charge:

```python
def getNonce(account, nonceKey) -> uint64:
    if nonceKey == 0:
        raise ERR(ProtocolNonceNotSupported)
    return R(nonce_slot(account, nonceKey))
```

Before T1, `nonceKey = 2^256 - 1` is an ordinary 2D key here and in the handler.

### 2.4 increment_nonce (internal)

Used by the handler for a transaction with a 2D nonce key (06-transactions-and-fees.md), after it
has checked `tx.nonce == getNonce(sender, nonce_key)`:

```python
def increment_nonce(account, nonce_key) -> uint64:
    if nonce_key == 0:
        raise ERR(InvalidNonceKey)
    s = nonce_slot(account, nonce_key)
    new = R(s) + 1
    if new > 2**64 - 1:
        raise ERR(NonceOverflow)
    W(s, new)
    LOG([NonceIncremented, account, nonce_key], abi_encode(uint64(new)))
    return new
```

The handler runs it with TIP-1060 accounting disabled and unmetered (its cost is part of intrinsic
gas). The `NonceIncremented` log is appended to the transaction's log list at that point, before any
call of the transaction executes. Which pre-execution logs appear in the receipt, in particular when
the call batch fails, is specified in 05-block-execution.md.

### 2.5 check_and_mark_expiring_nonce (internal, T1+)

Used by the handler for a transaction with `nonce_key = TEMPO_EXPIRING_NONCE_KEY` from T1. The
handler computes `replay_hash` (the transaction hash before T1B; from T1B
`keccak256(encode_for_signing(tx) || sender)`, see 02-encoding.md) and runs, with TIP-1060 accounting
disabled and unmetered:

```python
def check_and_mark_expiring_nonce(replay_hash, valid_before):
    cap  = EXPIRING_NONCE_SET_CAPACITY            # per active fork
    maxs = EXPIRING_NONCE_MAX_EXPIRY_SECS         # per active fork
    if valid_before <= now or valid_before > saturating_add(now, maxs):
        raise ERR(InvalidExpiringNonceExpiry)
    seen = R(seen_slot(replay_hash))
    if seen != 0 and seen > now:
        raise ERR(ExpiringNonceReplay)
    ptr = R(PTR_SLOT)
    old = R(ring_slot(ptr))
    if old != 0:
        old_expiry = R(seen_slot(old))
        if old_expiry != 0 and old_expiry > now:
            raise ERR(ExpiringNonceSetFull)
        W(seen_slot(old), 0)                      # evict the expired entry
    W(ring_slot(ptr), replay_hash)
    W(seen_slot(replay_hash), valid_before)
    W(PTR_SLOT, 0 if ptr + 1 >= cap else ptr + 1)
```

The pointer slot holds the wrapped index, never a running counter.

> **Resolved conflict C-KEY-09**: TIP-1009 stores `ptr + 1` unbounded and indexes with `ptr % CAPACITY`; the implementation stores the wrapped pointer (as TIP-1093 states). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-09).

> **Resolved conflict C-KEY-08**: TIP-1009 keys replay protection on the transaction hash; from T1B the implementation keys it on `keccak256(encode_for_signing || sender)`. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-08).

**Capacity change at T11.** The T11 activation performs no state migration. The pointer value
written by the last pre-T11 expiring transaction (some `p < 300,000`) is used as is; from T11 the
pointer advances from `p` up to 2,999,999 and only then wraps to 0. Every pre-T11 hash has expired
by the first post-T11 block that reaches it (pre-T11 windows are at most 30 s). Consequently:

- ring indices `p .. 299,999` are reached first, by the first post-T11 expiring transactions. They
  hold pre-T11 hashes only if the pre-T11 pointer had wrapped at least once; each such hash is evicted
  (`seen[old] := 0`) when the pointer reaches it, and an empty index is filled without eviction;
- indices `300,000 .. 2,999,999` are empty on the first post-T11 lap, so no eviction happens there;
- indices `0 .. p - 1` hold the most recent pre-T11 hashes and are reached only after the pointer
  wraps at 3,000,000; those hashes are evicted then;
- the maximum validity window becomes 300 s for blocks at or after T11.

> **Resolved conflict C-KEY-14**: TIP-1093 says post-activation transactions are inserted into the previously unallocated ring slots rather than overwriting pre-activation entries; the implementation resumes at the stored pointer, so indices `p .. 299,999` (which hold pre-activation entries once the ring has wrapped) are overwritten first, after evicting their expired entries. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-14).

Because `valid_before` is committed to by the replay hash, a hash whose `seen` entry has expired can
never pass the window check again, so an expired entry is only ever removed by eviction.

Canonical execution MUST use only the stored pointer. A client MAY pre-seek the pointer outside
canonical execution (for example when speculatively prewarming state), provided the stored state and
every canonical result are unchanged.

## 3. SignatureVerifier

The SignatureVerifier (TIP-1020, extended by TIP-1049) verifies Tempo signatures for contracts. It
is a precompile from T3. It has no storage of its own; the keychain methods read AccountKeychain
storage.

### 3.1 ABI

| Function | Selector | Live |
|---|---|---|
| `recover(bytes32 hash, bytes signature) returns (address signer)` | `0x19045a25` | T3+ |
| `verify(address signer, bytes32 hash, bytes signature) returns (bool)` | `0x1a86b550` | T3+ |
| `verifyKeychain(address account, bytes32 hash, bytes signature) returns (bool)` | `0x6c0c731e` | T6+ |
| `verifyKeychainAdmin(address account, bytes32 hash, bytes signature) returns (bool)` | `0x5f6fc5b7` | T6+ |

Errors: `InvalidFormat()` `0x257aa23b`, `InvalidSignature()` `0x8baa579f`.
All four functions are views (allowed in static calls).

### 3.2 Constants

| Name | Value |
|---|---|
| `MAX_WEBAUTHN_SIGNATURE_LENGTH` | 2,048 (bytes of WebAuthn signature data after the type byte) |
| `MAX_CALLDATA_LEN` | `4 + 32*4 + ceil32(2048 + 1)` = **2,212** bytes |
| `SECP256K1_VERIFY_GAS` | 3,000 |
| `P256_VERIFY_GAS` | 8,000 |
| `WEBAUTHN_VERIFY_GAS` | 8,000 |

### 3.3 Dispatch

1. Charge the input cost (precompiles/00-framework.md; 6 gas per word before T11, 30 from T11).
2. If `len(calldata) > 2212`, revert with `InvalidFormat()`. This applies to every selector, known or
   not, and to otherwise valid calls carrying trailing bytes.
3. Dispatch per §3.1 (selector gating and argument decoding per the framework).

### 3.4 recover and verify

```python
def recover(hash, signature) -> Address:
    sig = decode_primitive(signature)                # 03-signatures.md §3.2; DecodeError -> InvalidFormat (no gas)
    deduct_gas({SECP256K1: 3000, P256: 8000, WEBAUTHN: 8000}[sig.type])
    signer = recover_primitive(sig, hash)            # see below
    if signer is FAILURE:
        raise ERR(InvalidSignature)
    return signer

def verify(signer, hash, signature) -> bool:
    return recover(hash, signature) == signer         # reverts instead of returning false on bad signatures
```

`decode_primitive` accepts exactly the primitive formats: 65 bytes (secp256k1, no type
byte), `0x01 || 129 bytes` (P256), `0x02 || 128..2048 bytes` (WebAuthn). Every other input,
including keychain signatures (`0x03`, `0x04`), configurable-account signatures (`0x05`) and empty
input, fails with `InvalidFormat`. A secp256k1 `v` outside the set of 03-signatures.md §4.1
(`0, 1, 27, 28, 35..255`) is a decode error and so also fails with `InvalidFormat`.

`recover_primitive(sig, hash)` is the per-type recovery of 03-signatures.md with `digest = hash`:
`secp256k1_recover` (§4.2, including the EIP-2 low-`s` rule and the `r`, `s` range checks),
`recover_p256` (§5.2) or `recover_webauthn` (§6.2). For WebAuthn the expected `clientDataJSON`
challenge is therefore the unpadded Base64URL encoding of the 32-byte `hash` argument (for
`verifyKeychain`, of the Keychain V2 digest, §3.5), under the acceptance rules of 03-signatures.md
§6.3. Any verification failure gives `FAILURE`. The verification gas is the flat amount above; the
WebAuthn per-byte calldata surcharge used for transaction signatures is not charged here.

### 3.5 verifyKeychain and verifyKeychainAdmin (T6+)

```python
def recover_keychain_key(hash, signature):
    sig = decode_tempo_signature(signature)          # 03-signatures.md §3.2; DecodeError -> InvalidFormat
    if not sig.is_keychain():          raise ERR(InvalidFormat)
    if sig.version == V1:              raise ERR(InvalidFormat)   # only 0x04 (Keychain V2)
    if not sig.inner.is_primitive():   raise ERR(InvalidFormat)   # e.g. an inner 0x05 signature
    signing_hash = keccak256(b"\x04" + hash + sig.user_address)  # keychain_effective_digest(V2, ...); not metered
    key_id = recover(signing_hash, encode(sig.inner))  # canonical re-encoding (03-signatures.md §7); gas and errors as in recover
    return sig.user_address, key_id

def verifyKeychain(account, hash, signature) -> bool:
    user, key_id = recover_keychain_key(hash, signature)
    if user != account:
        return False                                  # no storage read
    try:
        validate_keychain_authorization(account, key_id, now, None)   # §1.9.2: one R of the key word
        return True
    except KeychainError:                             # missing, revoked or expired
        return False

def verifyKeychainAdmin(account, hash, signature) -> bool:
    user, key_id = recover_keychain_key(hash, signature)
    if user != account:
        return False
    if key_id == account:
        return True                                   # signed by the root key; no storage read
    try:
        return validate_keychain_authorization(account, key_id, now, None).is_admin
    except KeychainError:
        return False
```

Through T13 the inner signature's type is not compared with the stored key type, and
`verifyKeychain` returns true for any active access key, admin or not. Storage or out-of-gas errors
propagate. Gas = input cost + the inner primitive's verification gas + (unless short-circuited) one
SLOAD of AccountKeychain `key_slot(account, key_id)`. That SLOAD is metered in the SignatureVerifier
call: it costs 2,100 if `(ACCOUNT_KEYCHAIN_ADDRESS, key_slot)` is cold and 100 if warm, adds that pair
and `ACCOUNT_KEYCHAIN_ADDRESS` to the access sets, and charges no account-access cost for
`ACCOUNT_KEYCHAIN_ADDRESS` (§0.1). The slot is already warm when the same transaction was signed by
that key (§1.9) or read it earlier.

## 4. Storage credits (TIP-1060)

From T7 every account owns a persistent storage-credit balance. Clearing one of its storage slots
(nonzero → zero) mints a credit; creating one (zero → nonzero) either pays `STORAGE_CREDIT_VALUE`
gas or consumes a credit, depending on the account's transaction-local mode. TIP-1060 defines the
economics; this section fixes the state encoding, the exact hook, the precompile and the places
where the protocol disables or redirects the accounting.

### 4.1 Constants

| Name | Value |
|---|---|
| `STORAGE_CREDITS_ADDRESS` | `0x1060000000000000000000000000000000000000` |
| `SSTORE_CREATE_COST` | 250,000 (`SstoreSetWithoutLoadCost` at T1 – T6, excluding the 100-gas `SstoreStatic` part) |
| `SSTORE_SET_COST` | 5,000 (`SstoreSetWithoutLoadCost` from T7, excluding the 100-gas `SstoreStatic` part) |
| `STORAGE_CREDIT_VALUE` | 245,000 (`SSTORE_CREATE_COST - SSTORE_SET_COST`) |
| `WarmStorageReadCost` | 100 |
| `ColdStorageAdditionalCost` | 2,000 |
| `WARM_SSTORE_RESET` | 2,900 (`SstoreStatic` 100 + `SstoreResetWithoutColdLoadCost` 2,800) |

The SSTORE names follow the split of [05-block-execution.md §1.7](../05-block-execution.md#17-gas-schedule-per-fork):
`SstoreSetWithoutLoadCost` and `SstoreResetWithoutColdLoadCost` exclude `SstoreStatic`, and
`WARM_SSTORE_RESET` is the full warm clean reset including it. The T7 changes to the general SSTORE
gas table (zero → nonzero set cost 5,000, set refund 5,000, clearing refund 0, refund quotient 1) are
specified in [05-block-execution.md §1.7](../05-block-execution.md#17-gas-schedule-per-fork).

### 4.2 Persistent state

The balance of account `A` is stored in the StorageCredits account's storage at slot

```python
def credit_slot(A: Address) -> int:
    return u256(pad32(A))          # the address itself, left-padded; no hashing
```

For example `credit_slot(0x1111111111111111111111111111111111111111) =
0x0000000000000000000000001111111111111111111111111111111111111111`.

Its value is the balance as an unsigned integer `< 2^64` (bits 64..255 are zero). A missing slot means
balance 0. No rule stores a word of `2^64` or more. If one is read, the outcome depends on the reader:
a metered read `R` of the slot (`balanceOf`, §4.6.5) is an out-of-range storage value and reverts with
`Panic(0x11)` as precompiles/00-framework.md §5 specifies, while the SSTORE hook (§4.4) and settlement
(§4.7) treat it as an internal invariant violation and block processing fails. This overrides the
framework's `Panic(0x11)` outcome for those two readers.

> **Resolved conflict C-KEY-11**: TIP-1060 describes the balance as `mapping(address => uint256 packed_state)`; the implementation stores it at slot `uint256(bytes32(account))` with no mapping hash. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-11).

### 4.3 Transient state

For each account `A`, the StorageCredits account's *transient* storage at slot `credit_slot(A)` holds:

| Bits | Field | Default |
|---|---|---|
| 0..63 | `mode`: 0 = Refund, 1 = Preserve, 2 = Direct (only bits 0..7 are interpreted) | 0 (Refund) |
| 64..127 | `budget` (u64): remaining Direct-mode credits; `2^64-1` = unlimited | 0 |
| 128..191 | unused, written as 0 | 0 |
| 192..255 | `pending_refunds` (u64): Refund-mode creations awaiting settlement | 0 |

It follows EIP-1153 semantics: journaled with call frames (reverted with the frame that wrote it) and
cleared at the end of the transaction. A mode byte above 2 is a fatal inconsistency (unreachable).

> **Resolved conflict C-KEY-12**: TIP-1060 describes the transient state as a mapping of a struct `{uint64 budget; uint8 mode; uint64 pending_refunds}`; the implementation uses the direct slot and the bit layout above. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-key-12).

### 4.4 The SSTORE hook

From T7, every SSTORE, whether executed by the `SSTORE` opcode or performed by a precompile through
`W`, runs this hook after the slot has been written in the journal and before the SSTORE's dynamic gas
is charged (for precompiles: after the static charge, see precompiles/00-framework.md; for the opcode:
after the EIP-2200 stipend sentry, the 100-gas static charge and the journal write). `owner` is the
account whose storage was written; `key` is the slot for precompile writes and absent for the opcode;
`O, P, N` are the slot's original, present (pre-write) and new values.

```python
def storage_credit_hook(owner, key, O, P, N):
    if (P == 0) == (N == 0):
        return                                     # does not cross the zero boundary: no charge
    if owner == STORAGE_CREDITS_ADDRESS:
        return                                     # its own bookkeeping: no credit accounting
    charge(100)                                    # WarmStorageReadCost
    s = credit_slot(owner)
    if is_cold(STORAGE_CREDITS_ADDRESS, s):
        charge(2000)                               # out of gas if unaffordable; the slot becomes warm
    credit = sload_unmetered(STORAGE_CREDITS_ADDRESS, s)
    changed = False
    if P != 0 and N == 0:                          # clear: mint
        if key is not None and is_non_creditable(owner, key):   # §4.6.4
            return
        if minting_enabled:                        # §4.6.3
            credit = min(credit + 1, 2**64 - 1)
            changed = True
    else:                                          # P == 0 and N != 0: creation
        st = tload(STORAGE_CREDITS_ADDRESS, s)     # not charged
        if st.mode == DIRECT and credit > 0 and st.budget > 0:
            credit -= 1
            changed = True
            if st.budget != 2**64 - 1:
                st.budget -= 1
                tstore(STORAGE_CREDITS_ADDRESS, s, st)     # not charged
        elif st.mode in (DIRECT, PRESERVE):
            charge(STORAGE_CREDIT_VALUE)
        else:                                      # REFUND
            charge(STORAGE_CREDIT_VALUE)
            st.pending_refunds = min(st.pending_refunds + 1, 2**64 - 1)
            tstore(STORAGE_CREDITS_ADDRESS, s, st)
    if changed:
        o, p = journal_sstore_unmetered(STORAGE_CREDITS_ADDRESS, s, credit)  # returns that slot's original/present
        if p != credit and o == p:
            charge(2900)                           # WARM_SSTORE_RESET, only for a clean change
```

`charge(x)` fails with out-of-gas if less than `x` gas remains. The unmetered journal reads and
writes are ordinary state changes (they revert with the frame, enter the state root, and warm the
slot) that cost nothing beyond the charges shown; in particular creating the credit slot never costs
`SSTORE_CREATE_COST`. A clear of a slot whose credit is saturated at `2^64 - 1` still performs the
(no-op) journal write. The hook runs only when it is enabled for the current storage context (§4.6).

Warm sets: the hook's balance read adds `(STORAGE_CREDITS_ADDRESS, credit_slot(owner))` and the account
`STORAGE_CREDITS_ADDRESS` to the transaction's EIP-2929 access sets, for opcode and precompile SSTOREs
alike, and charges no account-access cost for `STORAGE_CREDITS_ADDRESS`. The read is performed only if
it is affordable: when the slot is cold and less than 2,000 gas remains after the 100-gas charge, the
hook fails with out-of-gas before accessing the slot, and nothing is warmed (the failing frame undoes
its accesses anyway). The journal write touches the same, already warm, slot. The hook's `tload` and
`tstore` warm nothing.

### 4.5 Precompile ABI (T7+)

| Function | Selector | Kind |
|---|---|---|
| `balanceOf(address account) returns (uint64)` | `0x70a08231` | view: `R(credit_slot(account))` |
| `modeOf(address account) returns (Mode mode)` | `0x13668995` | view: `TR(credit_slot(account))`, returns `mode` |
| `budgetOf(address account) returns (uint64)` | `0x7865e71f` | view: `TR(credit_slot(account))`, returns `budget` |
| `setMode(Mode newMode)` | `0x21175b4a` | mutator |
| `setBudget(uint64 credits)` | `0xffe295c3` | mutator |

`Mode` is the ABI enum `{Refund, Preserve, Direct}` (3 members, values 0, 1, 2); selectors use its
canonical type `uint8`, and `newMode` is decoded as an enum under
[precompiles/00-framework.md §4.5](00-framework.md#45-abi-decoder-configuration): before T11 the low-order
byte of the word, a byte of 3 or more giving the out-of-range value that `setMode` rejects with
`InvalidMode`; from T11 a word of 3 or more is a decoding failure (empty revert data).

Errors: `InvalidMode()` `0xa0042b17`; `OnlyDirectCall()` `0xbc592142` is declared
but never raised. A `DELEGATECALL` or `CALLCODE` into this (or any Tempo) precompile reverts with
`DelegateCallNotAllowed()` (`0x0d89438e`) as precompiles/00-framework.md
specifies.

```python
def setMode(newMode):                       # msg.sender sets its own mode
    # decoding: before T11 the low-order byte of the word; from T11 a word > 2 fails decoding (empty revert)
    if newMode not in (0, 1, 2): raise ERR(InvalidMode)          # reachable before T11 only
    st = TR(credit_slot(msg.sender))
    st.mode = newMode
    st.budget = 2**64 - 1 if newMode == DIRECT else 0
    TW(credit_slot(msg.sender), st)          # pending_refunds kept

def setBudget(credits):
    st = TR(credit_slot(msg.sender))
    st.mode, st.budget = DIRECT, credits
    TW(credit_slot(msg.sender), st)
```

Both mutators reject static calls (framework). They write only transient storage.

### 4.6 Where accounting is disabled, restricted or redirected

The hook is enabled for every precompile storage context and every `SSTORE` opcode from T7, except as
listed here. "Storage context" means one invocation of a precompile (one EVM call into it, including
the internal calls it makes to other precompiles, which share the context) or one protocol
operation run by the handler or block executor.

#### 4.6.1 Contexts with accounting disabled

In these contexts the hook does not run at all: clears mint nothing, creations neither pay
`STORAGE_CREDIT_VALUE` nor consume credits nor add pending refunds. Their gas, if any, is defined by
the chapter named.

| Context | Defined in |
|---|---|
| seeding `tx_origin` (§1.9.1) and other transient per-transaction context | 06-transactions-and-fees.md |
| validating a keychain signature's access key and `set_transaction_key` | 06-transactions-and-fees.md |
| applying a transaction's `key_authorization` (§1.9.3), and the same-transaction fee spending-limit deduction that follows it | 06-transactions-and-fees.md |
| 2D nonce increment and expiring-nonce marking (§2.4, §2.5) | 06-transactions-and-fees.md |
| fee pre-collection and post-transaction fee settlement/refund (fee manager hooks) | precompiles/fee-manager.md |
| end-of-transaction credit settlement (§4.7) | this chapter |
| `CurrentCommittee.setCommitteeMembers`: disables accounting for the rest of that invocation before its first write | precompiles/validator-config-and-zones.md |

#### 4.6.2 Writes owned by StorageCredits

Any SSTORE whose owner is `STORAGE_CREDITS_ADDRESS` skips the hook (first lines of §4.4).

#### 4.6.3 Minting disabled

Within a storage context the protocol may disable minting only; creations are still accounted. It
stays disabled for the rest of that context:

- `TipFeeManager.distribute_fees`: disabled at entry, before reading `collected_fees`.
- the fee AMM's rebalance swap: disabled after the validator-token pull and before the user-token
  transfer.

Details are in precompiles/fee-manager.md.

#### 4.6.4 Non-creditable slots

At the start of every transaction the protocol empties a transaction-local set of non-creditable
slots. From T7, if the transaction's collected fee is nonzero, after fee pre-collection the protocol
records:

1. `(fee_token, balance slot of fee_payer in fee_token)` (slot derivation in precompiles/tip20.md);
2. if the fee payer is the transaction sender and the transaction's fee key is set: `(ACCOUNT_KEYCHAIN_ADDRESS,
   limit_slot(fee_payer, fee_key, fee_token))`, i.e. the `remaining` word `s0` of that row.

The fee key is the acting access key when it is an existing key with `enforce_limits`, or, for a
same-transaction authorize-and-use transaction, the authorized key when the fee is nonzero, the fee
payer is the sender and the authorization carries limits (06-transactions-and-fees.md). A precompile
clear (`P != 0, N == 0`) of a recorded `(owner, key)` pair pays the hook's read cost and then mints
nothing. Opcode SSTOREs never match (they pass no key), and these slots are only writable by
precompiles anyway.

#### 4.6.5 Mode and budget overrides

`preserve_storage_credits(owner)`, from T7: `setMode`-equivalent for `owner` with mode Preserve
(`TR; TW` of `credit_slot(owner)`). The StablecoinDEX and TIP20ChannelReserve call it for their own
address at the start of their state-changing entry points (precompiles/stablecoin-dex.md,
precompiles/tip20.md).

```python
def with_budget(owner, limit, f):            # returns (f's result, signed balance delta); T7+
    if limit == 0:
        before = R(credit_slot(owner)); v = f(); after = R(credit_slot(owner))
        return v, after - before
    setBudget_for(owner, limit)              # TR; TW (mode Direct, budget = limit)
    before = R(credit_slot(owner))
    result = f()                             # an error is held until the reset below
    after = R(credit_slot(owner))
    st = TR(credit_slot(owner))
    TW(credit_slot(owner), State(mode=PRESERVE, budget=0, pending_refunds=st.pending_refunds))
    return result, after - before            # re-raises f's error, if any

def track_minted_credits(owner, f):          # T7+
    before = R(credit_slot(owner)); v = f(); after = R(credit_slot(owner))
    if after < before: FATAL                 # the operation consumed credits unexpectedly
    return v, after - before
```

Before T7 both helpers just run `f` and report 0. Here `R` reads the StorageCredits slot, and `TR`/`TW`
access its transient slot, through the calling precompile's metered storage context. Each `R` adds
`(STORAGE_CREDITS_ADDRESS, credit_slot(owner))` and `STORAGE_CREDITS_ADDRESS` to the access sets and
charges no account-access cost (the first read in a transaction costs 2,100, later ones 100);
`TR`/`TW` warm nothing. `preserve_storage_credits` performs only `TR` and `TW`. How the DEX and channel reserve use the deltas is
specified in their chapters.

### 4.7 End-of-transaction settlement

After a transaction's top-level execution finishes successfully, from T7, the protocol settles
Refund-mode creations, with accounting disabled and without metering:

```python
def settle_storage_credit_refunds(tx_result):
    if not T7 or not tx_result.success:
        return                                    # failed transactions settle nothing
    refund = 0
    for (s, st) in all_transient_slots(STORAGE_CREDITS_ADDRESS):   # every account with a transient entry
        if st.pending_refunds == 0:
            continue
        balance = sload(STORAGE_CREDITS_ADDRESS, s)
        used = min(st.pending_refunds, balance)
        if used == 0:
            continue
        sstore(STORAGE_CREDITS_ADDRESS, s, balance - used)
        refund += used * STORAGE_CREDIT_VALUE
    tx_result.gas_refund += refund                # subject to the T7 refund rules in 05-block-execution.md
```

The result does not depend on iteration order. Where settlement sits relative to the fee refund is
specified in 06-transactions-and-fees.md.

## 5. Fork summary

| Fork | Changes in this chapter |
|---|---|
| T0 (mainnet genesis) | AccountKeychain with legacy `authorizeKey`, `revokeKey`, `updateSpendingLimit`, `getKey`, `getRemainingLimit` (raw read), `getTransactionKey`; `expiry > now` required on authorization; one-time limits in `s0` only; NonceManager 2D nonces |
| T1 | expiring nonces (key `2^256-1`; 30 s window; 300,000-entry ring; replay hash = transaction hash); handler checks the access key's signature type |
| T1B | expiring replay hash becomes `keccak256(encode_for_signing(tx) \|\| sender)` |
| T1C | fee refunds restore the spending limit (`refund_spending_limit`) |
| T2 | `ensure_admin_caller` requires `msg.sender == tx_origin`; `getRemainingLimit` reports 0 for missing or revoked keys |
| T3 | periodic limits (`s1`), `u128` cap, duplicate-token rejection; call scopes (`key_scopes`, `setAllowedCalls`, `removeAllowedCalls`, `getAllowedCalls`, transaction-level scope checks); `authorizeKey(address,uint8,KeyRestrictions)`; legacy `authorizeKey` returns `LegacyAuthorizeKeySelectorChanged`; `getRemainingLimit` replaced by `getRemainingLimitWithPeriod`; expired keys report zero limits; `AccessKeySpend` event; SignatureVerifier `recover`/`verify` (with the 2,212-byte calldata cap) |
| T4 | struct writes no longer read packed slots first; scopes validated before any upsert; recipient-rule TIP-20 check by prefix only (no account read); no delete of empty recipient sets |
| T5 | witnesses: `authorizeKey(...,bytes32)`, `burnKeyAuthorizationWitness`, `isKeyAuthorizationWitnessBurned`; `allowAnyCalls` with non-empty `allowedCalls` rejected |
| T6 | admin keys: `authorizeAdminKey`, `isAdminKey`, admin keys pass `ensure_admin_caller`; SignatureVerifier `verifyKeychain`, `verifyKeychainAdmin` |
| T7 | storage credits (§4); periodic zero sentinel `2^256-1` |
| T11 | expiring nonces: 300 s window, 3,000,000-entry ring (no migration); `DEDUP` charges and duplicates-first validation order for scopes; `signatureType` 3 or ≥ 4 reverts with empty data in the four authorize selectors |
| T12, T13 | no change to the precompile rules of this chapter (T12's expiring-nonce discriminator is a handler rule, 06-transactions-and-fees.md; T12's SSTORE stipend sentry is in precompiles/00-framework.md) |
