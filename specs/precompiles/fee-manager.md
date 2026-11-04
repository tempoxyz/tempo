# TipFeeManager and the Fee AMM

Status: normative. Applies to Tempo mainnet (chain id 4217) from genesis through T13, and to Moderato (chain id 42431) from its T0 activation. Fork predicates ("From T1C:", "Before T8:") are defined in [01-chain-and-forks.md](../01-chain-and-forks.md): fork *F* is active for a block iff `header.timestamp >= F.activation_time`.

This chapter specifies the FeeManager precompile: its storage, its public ABI (user and validator fee-token preferences, fee distribution, and the Fee AMM liquidity functions), and the two protocol-internal hooks (`collectFeePreTx`, `collectFeePostTx`) that the transaction handler calls to charge every transaction's fee. Where in the transaction pipeline the hooks are called, how the fee token is resolved, and the balance precheck are specified in [06-transactions-and-fees.md](../06-transactions-and-fees.md). Dispatch, input-gas charging, static-call rejection, ABI decoding strictness, revert encoding and the storage slot rules are specified in [00-framework.md](00-framework.md). TIP-20 internals used here (`transfer`, `systemTransferFrom`, `transfer_fee_pre_tx`, `transfer_fee_post_tx`, currency, quote token, pause) are specified in [tip20.md](tip20.md); TIP-403 authorization (`is_authorized_as`) in [tip403.md](tip403.md); access-key spending limits and storage credits (TIP-1060) in [account-keychain.md](account-keychain.md).

Reference implementation: crates/precompiles/src/tip_fee_manager/{mod.rs,amm.rs,dispatch.rs}, crates/contracts/src/precompiles/tip_fee_manager.rs, crates/evm/src/fee_manager.rs, crates/evm/src/handler/config.rs.

## 1. Address and constants

| Name | Value |
|---|---|
| `FEE_MANAGER` | `0xfeEC000000000000000000000000000000000000` (active from Genesis) |
| `PATH_USD` (`DEFAULT_FEE_TOKEN`) | `0x20C0000000000000000000000000000000000000` |
| `M` | 9970 (fee-swap rate 0.9970) |
| `N` | 9985 (rebalance rate 0.9985) |
| `SCALE` | 10000 |
| `MIN_LIQUIDITY` | 1000 |
| `U128_MAX` | 2^128 − 1 |

The FeeManager is a single precompile: the "TIPFeeAMM" and "FeeManager" interfaces below are two ABIs served by the same address over the same storage. The account at `FEE_MANAGER` is present in genesis (code marker as specified in [04-state-and-genesis.md](../04-state-and-genesis.md)); its initial storage, if any, comes from the genesis alloc.

All arithmetic below is on unsigned 256-bit integers unless a width is stated. `a // b` is floor division. "Overflow" in pseudocode raises `Panic(0x11)` (`PANIC_OVERFLOW`, encoded `0x4e487b71 ‖ uint256(0x11)`) unless another error is named. Division by zero inside a `checked_div` also raises `PANIC_OVERFLOW`.

## 2. Storage layout

### 2.1 Persistent storage (account storage of `FEE_MANAGER`)

| Slot | Field | Type | Key → value |
|---|---|---|---|
| 0 | `validatorTokens` | `mapping(address => address)` | validator (fee recipient) → preferred token; 0 = unset |
| 1 | `userTokens` | `mapping(address => address)` | fee payer → preferred token; 0 = unset |
| 2 | `collectedFees` | `mapping(address => mapping(address => uint256))` | validator → token → accrued amount |
| 3 | `pools` | `mapping(bytes32 => Pool)` | poolId → reserves (one slot) |
| 4 | `totalSupply` | `mapping(bytes32 => uint256)` | poolId → LP share supply |
| 5 | `liquidityBalances` | `mapping(bytes32 => mapping(address => uint256))` | poolId → holder → LP shares |

Slots 6 and 7 of persistent storage are never written.

Mapping slots follow Solidity: for a mapping at base slot `s` and key `k`, the value slot is `keccak256(pad32(k) ‖ uint256(s))`, where `pad32` left-pads an address to 32 bytes and a `bytes32` key is used as is. A nested mapping applies the rule twice: `collectedFees[v][t]` is at `keccak256(pad32(t) ‖ keccak256(pad32(v) ‖ uint256(2)))`.

`Pool` occupies one 32-byte word:

| Bytes (big-endian word) | Field |
|---|---|
| low 16 bytes (bits 0..127) | `reserveUserToken: uint128` |
| high 16 bytes (bits 128..255) | `reserveValidatorToken: uint128` |

i.e. `word = reserveValidatorToken << 128 | reserveUserToken`. Reading a Pool is one SLOAD; writing it is one SSTORE of the whole word.

### 2.2 Transient storage (EIP-1153, at `FEE_MANAGER`)

| Transient slot | Field | Type | Written by |
|---|---|---|---|
| 6 | `pendingFeeSwapReservation` | `mapping(bytes32 => uint128)` (value right-aligned) | `collectFeePreTx` (from T1C) |
| 7 | `twoHopIntermediate` | `address` (right-aligned) | `collectFeePreTx` (from T5) |

Transient slot keys use the same mapping rule as persistent ones (`pendingFeeSwapReservation[id]` at transient key `keccak256(id ‖ uint256(6))`). As with all transient storage, both are zero at the start of every transaction and are discarded at its end; a value written by one transaction is never observed by another.

### 2.3 Pool id

```python
def pool_id(user_token: address, validator_token: address) -> bytes32:
    return keccak256(pad32(user_token) + pad32(validator_token))   # abi.encode(userToken, validatorToken)
```

Pools are directional: `pool_id(A, B) != pool_id(B, A)`. Pool `(A, B)` holds `reserveUserToken` in token A and `reserveValidatorToken` in token B; fee swaps move A in and B out, rebalance swaps move B in and A out.

## 3. ABI

### 3.1 Functions

| Function | Selector | Kind | Section |
|---|---|---|---|
| `userTokens(address user) returns (address)` | `0xed498fa8` | view | 4.3 |
| `validatorTokens(address validator) returns (address)` | `0x6dc54a7a` | view | 4.3 |
| `setUserToken(address token)` | `0xe7897444` | mutate | 4.2 |
| `setValidatorToken(address token)` | `0xb60d2ddb` | mutate | 4.1 |
| `distributeFees(address validator, address token)` | `0xa6c07924` | mutate | 6 |
| `collectedFees(address validator, address token) returns (uint256)` | `0x4c97f766` | view | 4.3 |
| `M() returns (uint256)` | `0x693f917e` | view | returns 9970 |
| `N() returns (uint256)` | `0xc9e525df` | view | returns 9985 |
| `SCALE() returns (uint256)` | `0xeced5526` | view | returns 10000 |
| `MIN_LIQUIDITY() returns (uint256)` | `0x21b77d63` | view | returns 1000 |
| `getPoolId(address userToken, address validatorToken) returns (bytes32)` | `0x2ef61c21` | view | `pool_id`, no storage access |
| `getPool(address userToken, address validatorToken) returns (Pool)` | `0x531aa03e` | view | SLOAD `pools[pool_id(u, v)]` |
| `pools(bytes32 poolId) returns (Pool)` | `0xb5217bb4` | view | SLOAD `pools[poolId]` |
| `totalSupply(bytes32 poolId) returns (uint256)` | `0xb524abcf` | view | SLOAD `totalSupply[poolId]` |
| `liquidityBalances(bytes32 poolId, address user) returns (uint256)` | `0x4fb5bf7f` | view | SLOAD `liquidityBalances[poolId][user]` |
| `mint(address userToken, address validatorToken, uint256 amountValidatorToken, address to) returns (uint256 liquidity)` | `0xf1aa8cb8` | mutate | 5.1 |
| `burn(address userToken, address validatorToken, uint256 liquidity, address to) returns (uint256 amountUserToken, uint256 amountValidatorToken)` | `0xfa291e53` | mutate | 5.2 |
| `rebalanceSwap(address userToken, address validatorToken, uint256 amountOut, address to) returns (uint256 amountIn)` | `0x1bd94ac7` | mutate | 5.3 |

`Pool` is ABI-encoded as the static tuple `(uint128 reserveUserToken, uint128 reserveValidatorToken)` (64 bytes). Functions without returns produce empty return data. "mutate" functions are rejected in a static context and "view" functions are not, as specified in [00-framework.md](00-framework.md). No selector is fork-scheduled: all of the above are served from Genesis. `collectFeePreTx` and `collectFeePostTx` are not part of the ABI; calldata naming them is an unknown selector.

### 3.2 Events

All events are emitted by `FEE_MANAGER`.

| Event | topic0 | Indexed (topics 1..3) | Data |
|---|---|---|---|
| `UserTokenSet(address indexed user, address indexed token)` | `0xabc7758d4ca817ce0d125eb731121a1304c36077b791253be835b95472368856` | user, token | — |
| `ValidatorTokenSet(address indexed validator, address indexed token)` | `0x6eb51f8f7e857fb2caf4257da4219a86adeed7128412764e41334968165f5f0c` | validator, token | — |
| `FeesDistributed(address indexed validator, address indexed token, uint256 amount)` | `0xfe29ed2b7edbf126f3c1660fa23703a1c600aff44409f07b3c848bbb03631f95` | validator, token | amount |
| `Mint(address sender, address indexed to, address indexed userToken, address indexed validatorToken, uint256 amountValidatorToken, uint256 liquidity)` | `0xf114ca9eb82947af39f957fa726280fd3d5d81c3d7635a4aeb5c302962856eba` | to, userToken, validatorToken | sender, amountValidatorToken, liquidity |
| `Burn(address indexed sender, address indexed userToken, address indexed validatorToken, uint256 amountUserToken, uint256 amountValidatorToken, uint256 liquidity, address to)` | `0xa1306df62797fd30333308e15e2db0aed324580be7f22c124614a44310ec7fcc` | sender, userToken, validatorToken | amountUserToken, amountValidatorToken, liquidity, to |
| `RebalanceSwap(address indexed userToken, address indexed validatorToken, address indexed swapper, uint256 amountIn, uint256 amountOut)` | `0x1e9bc167ac8bc86f20f6d5c4c24338e554a9ae0f92faa67d1e2f59fe4a89c97f` | userToken, validatorToken, swapper | amountIn, amountOut |

Fee swaps executed by the hooks emit no FeeManager event.

### 3.3 Errors

Errors raised by FeeManager code:

| Error | Selector |
|---|---|
| `InvalidToken()` | `0xc1ab6dc1` |
| `CannotChangeWithinBlock()` | `0x82946ea1` |
| `IdenticalAddresses()` | `0xbd969eb0` |
| `InsufficientLiquidity()` | `0xbb55fd27` |
| `InsufficientReserves()` | `0x945e9268` |
| `InvalidAmount()` | `0x2c5211c6` |
| `DivisionByZero()` | `0x23d359a3` |
| `InvalidSwapCalculation()` | `0x337e5a83` |
| `Panic(uint256)` with code `0x11` | `0x4e487b71` |

`InsufficientFeeTokenBalance()` (`0x04ae7426`) is declared in the ABI but never raised. Both interfaces declare `InvalidToken()`; it has one selector.

Errors raised by TIP-20 / TIP-403 code reached from the FeeManager propagate unchanged, among them `InvalidToken()` (`0xc1ab6dc1`, the TIP-20 prefix check: same selector as FeeManager's), `InvalidCurrency()` (`0xf5993428`), `PolicyForbids()` (`0x54cfe659`), `ContractPaused()` (`0xab35696f`), `InsufficientBalance(uint256 available, uint256 required, address token)` (`0x832f98b5`), `InvalidRecipient()` (`0x9c8d2cd2`), `Unauthorized()` (`0x82b42900`) and `SpendingLimitExceeded()` (`0x8a9e71ea`, from AccountKeychain).

## 4. Common definitions

```python
def compute_amount_out(amount_in: uint256) -> uint256:
    # fee-swap output at M/SCALE, rounded down
    return checked_mul(amount_in, M) // SCALE          # overflow -> PANIC_OVERFLOW

def has_enough_reserve_validator_token(pool: Pool, amount: uint256) -> bool:
    # An empty pool is never sufficient, even for a zero output.
    return pool.reserveValidatorToken != 0 and pool.reserveValidatorToken >= amount

def get_validator_token(validator: address) -> address:
    t = sload(validatorTokens[validator])
    return PATH_USD if t == 0 else t

def require_tip20_prefix(token):            # TIP20Token::from_address
    if token[0:12] != 0x20C000000000000000000000: raise TIP20.InvalidToken
    # no storage access

def is_deployed_tip20(token) -> bool:       # TIP20Factory.is_tip20
    return token[0:12] == 0x20C000000000000000000000 and code_hash(token) != EMPTY_CODE_HASH
    # one account access (warm/cold per 00-framework.md); no SLOAD

def validate_usd_currency(token):
    require_tip20_prefix(token)             # TIP20.InvalidToken
    if tip20_currency(token) != "USD":      # reads the token's currency string (tip20.md)
        raise TIP20.InvalidCurrency
```

A token address with the TIP-20 prefix but no code reads an empty currency string and so fails `validate_usd_currency` with `InvalidCurrency`.

`tip403_require(token, [(addr, role), ...])` reads the token's `transferPolicyId` once, then evaluates `TIP403Registry.is_authorized_as(policy_id, addr, role)` for each pair **in order**, raising `TIP20.PolicyForbids` at the first `false` (later pairs are not evaluated). `role` is SENDER or RECIPIENT as defined in [tip403.md](tip403.md).

`tip20_ensure_transfer_authorized(token, from, to)` reads `transferPolicyId`, evaluates SENDER for `from`; **from T2**, if that is false it raises `PolicyForbids` without evaluating the recipient; otherwise (and always before T2) it evaluates RECIPIENT for `to` and raises `PolicyForbids` if either is false.

`msg_sender` below is the caller of the precompile frame; `block.beneficiary` is the header's beneficiary (coinbase) of the block being executed.

### 4.1 setValidatorToken(token)

```python
def setValidatorToken(token):
    if not is_deployed_tip20(token): raise InvalidToken                 # FeeManager error
    if msg_sender == block.beneficiary: raise CannotChangeWithinBlock
    validate_usd_currency(token)                                         # TIP20.InvalidCurrency
    sstore(validatorTokens[msg_sender], token)
    emit ValidatorTokenSet(msg_sender, token)
```

The write and event happen even when the stored value already equals `token`. The zero address fails the first check, so a validator cannot unset its preference; setting `PATH_USD` explicitly is equivalent to unset for every reader.

### 4.2 setUserToken(token)

```python
def setUserToken(token):
    if not is_deployed_tip20(token): raise InvalidToken
    validate_usd_currency(token)
    if T3_active:
        if sload(userTokens[msg_sender]) == token:
            return                                   # no write, no event
    sstore(userTokens[msg_sender], token)
    emit UserTokenSet(msg_sender, token)
```

Before T3 the write and the event happen even when the value is unchanged.

> **Resolved conflict C-FEE-05**: docs state the unchanged-token no-op unconditionally; code applies it only from T3. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-05).

A top-level `setUserToken` call also affects fee-token resolution for its own transaction; that rule is in [06-transactions-and-fees.md](../06-transactions-and-fees.md).

### 4.3 Views

- `userTokens(user)` returns the raw stored value (zero when unset).
- `validatorTokens(validator)` returns `get_validator_token(validator)`: `PATH_USD` when unset.
- `collectedFees(validator, token)` returns the raw stored value.

## 5. Fee AMM liquidity functions

The pseudocode lists every storage access in execution order; gas for each is charged as specified in [00-framework.md](00-framework.md), so an implementation MUST perform the same accesses in the same order (including repeated reads and repeated writes of the same slot) to reproduce `gasUsed`. Checks are performed in the order shown; the first failing check determines the revert data.

### 5.1 mint

```python
def mint(user_token, validator_token, amount, to) -> uint256:
    if user_token == validator_token: raise IdenticalAddresses
    if amount == 0: raise InvalidAmount
    validate_usd_currency(user_token)
    validate_usd_currency(validator_token)
    if T8_active:
        tip403_require(user_token, [(msg_sender, SENDER), (FEE_MANAGER, RECIPIENT), (to, RECIPIENT)])
        tip403_require(validator_token, [(to, RECIPIENT)])
    id = pool_id(user_token, validator_token)
    pool = sload(pools[id])
    total_supply = sload(totalSupply[id])

    if pool.reserveUserToken == 0 and pool.reserveValidatorToken == 0:
        half = amount // 2
        if half <= MIN_LIQUIDITY: raise InsufficientLiquidity
        total_supply = checked_add(total_supply, MIN_LIQUIDITY)          # PANIC_OVERFLOW
        sstore(totalSupply[id], total_supply)                            # first write
        liquidity = half - MIN_LIQUIDITY
    else:
        product = (N * pool.reserveUserToken) // SCALE                   # (overflow -> InvalidSwapCalculation; unreachable)
        denom = checked_add(pool.reserveValidatorToken, product)         # overflow -> InvalidAmount
        if denom == 0: raise DivisionByZero
        liquidity = checked_mul(amount, total_supply) // denom           # overflow -> InvalidSwapCalculation

    if liquidity == 0: raise InsufficientLiquidity

    tip20_system_transfer_from(validator_token, caller=FEE_MANAGER, from_=msg_sender, amount=amount)

    if amount > U128_MAX: raise InvalidAmount
    pool.reserveValidatorToken = checked_add_u128(pool.reserveValidatorToken, amount)   # overflow -> InvalidAmount
    sstore(pools[id], pool)
    sstore(totalSupply[id], checked_add(total_supply, liquidity))        # PANIC_OVERFLOW
    bal = sload(liquidityBalances[id][to])
    sstore(liquidityBalances[id][to], checked_add(bal, liquidity))       # PANIC_OVERFLOW
    emit Mint(msg_sender, to, user_token, validator_token, amount, liquidity)
    return liquidity
```

Rules that follow from the pseudocode and MUST hold:

- Only the validator-token reserve increases; the user-token reserve is unchanged, also on the first deposit.
- On initialization (both reserves zero) `MIN_LIQUIDITY` shares are added to `totalSupply` with no holder and the depositor receives `amount // 2 − MIN_LIQUIDITY`. If both reserves are zero while `totalSupply` is already nonzero (all redeemable shares burned and both reserves rounded to zero), the branch adds another `MIN_LIQUIDITY` on top of the existing supply.
- On a subsequent deposit `liquidity = amount × totalSupply // (V + N × U // SCALE)`, with `U, V` the reserves before the deposit.
- `tip20_system_transfer_from` moves `amount` of `validator_token` from `msg_sender` to `FEE_MANAGER` with no allowance, applying pause, TIP-403 (`msg_sender` as sender, FeeManager as recipient), receive-policy and access-key spending-limit rules ([tip20.md](tip20.md)). From T5 it requires the caller (FeeManager) to be on the Implicit Approval List (it is).
- Before T8 `mint` performs no TIP-403 check other than those inside that transfer.

> **Resolved conflict C-FEE-04**: docs state the T8 mint/burn/pre-collection authorization rules unconditionally; code applies them only from T8. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-04).

> **Resolved conflict C-FEE-06**: TIP-1042 reads both tokens' policy ids before evaluating any authorization; code finishes the userToken checks before reading the validatorToken policy. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-fee-06).

### 5.2 burn

```python
def burn(user_token, validator_token, liquidity, to) -> (uint256, uint256):
    if user_token == validator_token: raise IdenticalAddresses
    if liquidity == 0: raise InvalidAmount
    validate_usd_currency(user_token)
    validate_usd_currency(validator_token)
    if T8_active:
        tip403_require(user_token, [(msg_sender, SENDER)])
        tip403_require(validator_token, [(msg_sender, SENDER)])
    id = pool_id(user_token, validator_token)
    bal = sload(liquidityBalances[id][msg_sender])
    if bal < liquidity: raise InsufficientLiquidity
    pool = sload(pools[id])
    ts = sload(totalSupply[id])                                           # first read
    amount_user = checked_mul(liquidity, pool.reserveUserToken) // ts           # PANIC_OVERFLOW (incl. ts == 0)
    amount_validator = checked_mul(liquidity, pool.reserveValidatorToken) // ts # PANIC_OVERFLOW
    if amount_validator > U128_MAX: raise InvalidAmount
    if amount_validator > pool.reserveValidatorToken: raise InsufficientReserves
    if T1C_active:
        reserved = tload(pendingFeeSwapReservation[id])
        if pool.reserveValidatorToken - amount_validator < reserved: raise InsufficientLiquidity
    sstore(liquidityBalances[id][msg_sender], bal - liquidity)
    ts2 = sload(totalSupply[id])                                          # second read (warm)
    sstore(totalSupply[id], ts2 - liquidity)                              # PANIC_OVERFLOW on underflow
    if amount_user > U128_MAX: raise InvalidAmount
    if amount_validator > U128_MAX: raise InvalidAmount
    if amount_user > pool.reserveUserToken: raise InsufficientReserves
    pool.reserveUserToken -= amount_user
    pool.reserveValidatorToken -= amount_validator                       # InsufficientReserves on underflow
    sstore(pools[id], pool)
    tip20_transfer(user_token, sender=FEE_MANAGER, to=to, amount=amount_user)
    tip20_transfer(validator_token, sender=FEE_MANAGER, to=to, amount=amount_validator)
    emit Burn(msg_sender, user_token, validator_token, amount_user, amount_validator, liquidity, to)
    return (amount_user, amount_validator)
```

- Payouts are `floor(liquidity × reserve / totalSupply)` per token, using `totalSupply` before this burn.
- Both payout transfers are ordinary TIP-20 `transfer`s with FeeManager as `msg.sender` ([tip20.md](tip20.md)): user token first, then validator token, each emitting its TIP-20 `Transfer` (and any virtual-address or receive-policy events) before `Burn`. A transfer is made even when its amount is zero, so pause, recipient validation and TIP-403 checks (FeeManager as sender, `to` as recipient) apply to zero payouts too.

> **Resolved conflict C-FEE-07**: docs say the payout-side checks apply to each nonzero payout; code performs both transfers, and their checks, even for a zero amount. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-07).

- TIP-1060 credit minting is **not** disabled in `burn` (Section 8).

### 5.3 rebalanceSwap

Sells `amountOut` of the pool's user token for validator token at the rebalance rate.

```python
def rebalanceSwap(user_token, validator_token, amount_out, to) -> uint256:
    if amount_out == 0: raise InvalidAmount
    id = pool_id(user_token, validator_token)
    pool = sload(pools[id])
    amount_in = checked_mul(amount_out, N) // SCALE + 1                  # PANIC_OVERFLOW
    if amount_in > U128_MAX: raise InvalidAmount
    if amount_out > U128_MAX: raise InvalidAmount
    new_v = pool.reserveValidatorToken + amount_in
    if new_v > U128_MAX: raise InsufficientReserves
    if amount_out > pool.reserveUserToken: raise InvalidAmount
    pool.reserveValidatorToken = new_v
    pool.reserveUserToken -= amount_out
    if T1C_active:
        reserved = tload(pendingFeeSwapReservation[id])
        if pool.reserveValidatorToken < reserved: raise InsufficientLiquidity
    sstore(pools[id], pool)
    require_tip20_prefix(validator_token)                                 # TIP20.InvalidToken
    tip20_system_transfer_from(validator_token, caller=FEE_MANAGER, from_=msg_sender, amount=amount_in)
    if T7_active: disable_storage_credit_minting()                        # Section 8
    require_tip20_prefix(user_token)
    tip20_transfer(user_token, sender=FEE_MANAGER, to=to, amount=amount_out)
    emit RebalanceSwap(user_token, validator_token, msg_sender, amount_in, amount_out)
    return amount_in
```

- `amountIn = floor(amountOut × 9985 / 10000) + 1`: one base unit is added even when the division is exact.
- No identical-token, prefix or currency validation precedes the pool read; an invalid pair has zero reserves and fails at `amount_out > reserveUserToken` with `InvalidAmount`.
- The pool is written before either token moves.
- Anyone may call it; TIP-403 applies only through the two transfers (`msg_sender` → FeeManager in validator token; FeeManager → `to` in user token).

## 6. distributeFees

```python
def distributeFees(validator, token):
    if T7_active: disable_storage_credit_minting()                        # before any storage access
    amount = sload(collectedFees[validator][token])
    if amount == 0:
        return                                                            # no transfer, no event
    sstore(collectedFees[validator][token], 0)
    require_tip20_prefix(token)
    tip20_transfer(token, sender=FEE_MANAGER, to=validator, amount=amount)
    emit FeesDistributed(validator, token, amount)
```

There is no access control: anyone may trigger distribution to `validator`. The transfer is an ordinary TIP-20 `transfer` from FeeManager: pause, recipient validation, TIP-403 (FeeManager as sender, `validator` as recipient) and, from T6, receive-policy handling apply; a receive-policy rejection that holds the funds in ReceivePolicyGuard still counts as success, and `FeesDistributed` is still emitted. Log order: the TIP-20 transfer's logs, then `FeesDistributed`. If the transfer reverts, the whole call reverts and `collectedFees` is unchanged.

## 7. Protocol fee hooks

### 7.1 Invocation contract

The transaction handler ([06-transactions-and-fees.md](../06-transactions-and-fees.md) fixes their position in the pipeline) calls two internal entry points of the FeeManager for every transaction that pays fees. They are Rust-level calls, not EVM messages:

- They run with `FEE_MANAGER` as the storage owner, directly against the transaction's state journal, with **no gas metering**: their storage reads, writes, transient accesses and logs are charged to no gas budget and do not count toward the transaction's `gasUsed`. The accounts and slots they touch are warm (EIP-2929) for the rest of the transaction.
- They run with TIP-1060 storage-credit accounting **disabled**: their SSTOREs neither mint nor consume storage credits nor create pending refunds ([account-keychain.md](account-keychain.md)).
- Any error they return makes the transaction **invalid**: a block that contains it is invalid. (Implementations report insufficient AMM liquidity, insufficient fee-token balance, a paused fee token and other failures as distinct invalidity reasons; the reason does not affect consensus.)

Amounts, with `effective_gas_price` and `tx_gas_used` as defined in [06-transactions-and-fees.md](../06-transactions-and-fees.md) and `ceil_div(a, b) = (a + b − 1) // b`:

```python
collected       = ceil_div(tx.gas_limit * effective_gas_price, 10**12)   # maxAmount
actual_spending = ceil_div(tx_gas_used * effective_gas_price, 10**12)
refund          = collected - actual_spending                            # each term rounded separately
fee_payer       = the transaction's fee payer
fee_token       = the transaction's resolved fee token (resolved once, before the pre hook)
beneficiary     = block.beneficiary
```

Call rules:

1. `collectFeePreTx(fee_payer, fee_token, collected, beneficiary)` is called once, before execution, **iff `collected != 0`**. If it fails, every state change it made is rolled back and the transaction is invalid.
2. `collectFeePostTx(fee_payer, actual_spending, refund, fee_token, beneficiary)` is called once, after execution and gas finalization, whether execution succeeded, reverted or halted, **unless** `actual_spending == 0 and refund == 0` (it is also not called when `collected == 0 and actual_spending != 0`, which cannot occur). Its effects and logs are not undone by an execution revert. If it fails, the transaction is invalid.
3. Block execution MUST perform the liquidity check and reservation of Section 7.2. (The reference implementation has a `skip_liquidity_check` flag that only its transaction pool sets; block building and validation never set it.)

Because the base fee is never below its floor (`6 × 10^8` from T7, higher before), `collected ≥ 1` for any `gas_limit ≥ 1` in block execution, so the pre hook runs for every fee-paying transaction.

The post hook's return value (the amount credited to the validator) is not part of consensus; the reference payload builder uses it to rank blocks.

### 7.2 collectFeePreTx

```python
def collectFeePreTx(fee_payer, user_token, max_amount, beneficiary):
    validator_token = get_validator_token(beneficiary)                    # SLOAD validatorTokens[beneficiary]
    require_tip20_prefix(user_token)                                      # TIP20.InvalidToken
    if T8_active:
        tip403_require(user_token, [(fee_payer, SENDER)])
    else:
        tip20_ensure_transfer_authorized(user_token, fee_payer, FEE_MANAGER)   # sender AND FeeManager as recipient
    tip20_transfer_fee_pre_tx(user_token, fee_payer, max_amount)          # moves max_amount payer -> FeeManager
    route = plan_fee_route(user_token, validator_token, max_amount)       # Section 7.3
    if route is None: raise InsufficientLiquidity
    reserve_fee_liquidity(user_token, validator_token, max_amount, route) # Section 7.4
```

`tip20_transfer_fee_pre_tx` ([tip20.md](tip20.md)) raises `ContractPaused` if the token is paused, debits the access key's spending limit when the transaction is keychain-signed by the fee payer (`SpendingLimitExceeded`), updates the payer's reward accounting, debits `max_amount` from the payer (`InsufficientBalance`) and credits it to `FEE_MANAGER`. It emits no log.

Before T8 the pre hook requires the fee payer to be an authorized sender **and** `FEE_MANAGER` to be an authorized recipient under the fee token's transfer policy; from T8 only the fee payer is checked (TIP-1042).

> **Resolved conflict C-FEE-04**: docs state the T8 mint/burn/pre-collection authorization rules unconditionally; code applies them only from T8. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-04).

The fee is collected **before** the route is planned; the liquidity check then decides validity.

> **Resolved conflict C-FEE-03**: the Fee AMM doc says pre-collection checks liquidity before collecting; code collects first, then checks. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-03).

### 7.3 Route planning and the liquidity sufficiency predicate

```python
def plan_fee_route(user_token, validator_token, max_amount):
    if user_token == validator_token:
        return SAME_TOKEN
    out1 = compute_amount_out(max_amount)                                 # floor(max * 9970 / 10000)
    direct = sload(pools[pool_id(user_token, validator_token)])
    if has_enough_reserve_validator_token(direct, out1):
        return DIRECT
    if not T5_active:
        return None
    mid = tip20_quote_token(user_token)                                   # SLOAD of the token's quoteToken
    if mid == 0 or mid == validator_token:
        return None
    leg1 = sload(pools[pool_id(user_token, mid)])
    if not has_enough_reserve_validator_token(leg1, out1):
        return None
    out2 = compute_amount_out(out1)                                       # floor(out1 * 9970 / 10000)
    leg2 = sload(pools[pool_id(mid, validator_token)])
    if not has_enough_reserve_validator_token(leg2, out2):
        return None
    return TWO_HOP(mid)
```

The liquidity sufficiency predicate is therefore, for a pool `P` and required output `x`: `P.reserveValidatorToken != 0 and P.reserveValidatorToken >= x`. It compares against the reserve as stored; reservations (which are per transaction) are not subtracted. The required output is computed from `max_amount` (`collected`), not from the eventual `actual_spending`. The direct pool is always tried first; the two-hop path through `userToken.quoteToken()` exists only from T5 and is skipped when the quote token is zero (pathUSD has none) or equals the validator token. A TIP-20 never quotes itself, so `mid != user_token`.

### 7.4 Liquidity reservation (from T1C)

```python
def reserve_fee_liquidity(user_token, validator_token, max_amount, route):
    if route == SAME_TOKEN:
        return
    if route == DIRECT:
        if T1C_active:
            out = compute_amount_out(max_amount)            # > U128_MAX -> PANIC_OVERFLOW (unreachable)
            tstore(pendingFeeSwapReservation[pool_id(user_token, validator_token)], out)
        return
    # TWO_HOP(mid); only reachable from T5, which implies T1C
    out1 = compute_amount_out(max_amount)
    out2 = compute_amount_out(out1)
    tstore(pendingFeeSwapReservation[pool_id(user_token, mid)], out1)
    tstore(pendingFeeSwapReservation[pool_id(mid, validator_token)], out2)
    tstore(twoHopIntermediate, mid)
```

Semantics:

- The reserved amount is in **validator-token units of that pool** (the pool's `reserveValidatorToken` side): `floor(max_amount × 9970 / 10000)` for the direct pool or the first leg, and `floor(floor(max_amount × 9970 / 10000) × 9970 / 10000)` for the second leg. It is not `max_amount`.
- A `tstore` overwrites; reservations are not additive. (Within one transaction only the pre hook writes them, and the two legs are always distinct pools.)
- From T1C, `burn` and `rebalanceSwap` on a pool revert with `InsufficientLiquidity` if the pool's `reserveValidatorToken` after the operation would be below that pool's reservation (Sections 5.2, 5.3). `mint` and the post hook's swaps do not read it.
- Because transient storage lives for one transaction, the reservation constrains only the paying transaction's own execution. It guarantees that the post-hook swap of `actual_spending ≤ collected` cannot fail for lack of reserves.
- Before T1C there is no reservation: the transaction's own execution can drain the pool, and the post hook then fails with `InsufficientLiquidity`, which makes the transaction invalid (Section 7.1).

> **Resolved conflict C-FEE-01**: spec-fee.mdx says the pre-collection reserves max_fee of liquidity; code reserves floor(maxAmount × 0.997) validator-token units (nested floor on leg 2), and only from T1C. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](../conflicts.md#c-fee-01).

> **Resolved conflict C-FORKS-04**: TIP-1036 lists the reserved-liquidity transient guard (and the fee-refund spending-limit restore) as T2 changes; code activates both at T1C. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-forks-04).

### 7.5 collectFeePostTx

```python
def collectFeePostTx(fee_payer, actual_spending, refund, fee_token, beneficiary) -> uint256:
    require_tip20_prefix(fee_token)                                       # TIP20.InvalidToken
    tip20_transfer_fee_post_tx(fee_token, fee_payer, refund, actual_spending)
    hop = tload(twoHopIntermediate)                                       # 0 unless the pre hook chose TWO_HOP
    validator_token = get_validator_token(beneficiary)                    # SLOAD
    if fee_token == validator_token:
        amount = actual_spending
    elif hop == 0:
        if actual_spending != 0:
            execute_fee_swap(fee_token, validator_token, actual_spending)
        amount = compute_amount_out(actual_spending)
    else:
        if actual_spending != 0:
            out1 = execute_fee_swap(fee_token, hop, actual_spending)
            execute_fee_swap(hop, validator_token, out1)
        amount = compute_amount_out(compute_amount_out(actual_spending))
    if amount != 0:
        v = sload(collectedFees[beneficiary][validator_token])
        sstore(collectedFees[beneficiary][validator_token], checked_add(v, amount))   # PANIC_OVERFLOW
    return amount

def execute_fee_swap(user_token, validator_token, amount_in) -> uint256:
    amount_out = compute_amount_out(amount_in)
    id = pool_id(user_token, validator_token)
    pool = sload(pools[id])
    if amount_out > pool.reserveValidatorToken: raise InsufficientLiquidity
    if amount_in > U128_MAX or amount_out > U128_MAX: raise PANIC_OVERFLOW
    pool.reserveUserToken = checked_add_u128(pool.reserveUserToken, amount_in)   # PANIC_OVERFLOW
    pool.reserveValidatorToken -= amount_out
    sstore(pools[id], pool)
    return amount_out
```

`tip20_transfer_fee_post_tx` ([tip20.md](tip20.md)), in this order: emits `Transfer(fee_payer, FEE_MANAGER, actual_spending)` at the fee-token address (always, even when `actual_spending == 0`); returns if `refund == 0`; **from T1C** restores `refund` to the access key's spending limit (`AccountKeychain.refund_spending_limit(fee_payer, fee_token, refund)`, [account-keychain.md](account-keychain.md)); updates the payer's reward accounting; debits `refund` from `FEE_MANAGER` and credits it to `fee_payer`. It performs no pause check and no TIP-403 or receive-policy check, so a refund succeeds even if the transaction paused the token or changed its policy.

> **Resolved conflict C-FORKS-04**: TIP-1036 dates the fee-refund spending-limit restore at T2; code applies it from T1C. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](../conflicts.md#c-forks-04).

Consequences that MUST hold:

- The validator is credited `actual_spending` (same token), `floor(actual_spending × 9970 / 10000)` (direct), or `floor(floor(actual_spending × 9970 / 10000) × 9970 / 10000)` (two-hop), always in `get_validator_token(beneficiary)` and to `collectedFees[beneficiary][validator_token]`. The credited amount equals the last swap's output, so the FeeManager's token balances back every `collectedFees` entry and pool reserve.
- The swap path is the one the pre hook chose: the intermediate comes from transient storage, not from a fresh `quoteToken()` read, so a quote-token change during the transaction does not change routing.
- The validator token is read again from storage. It cannot have changed during the transaction: only `validatorTokens[beneficiary]` is read, and `setValidatorToken` rejects the beneficiary as caller.
- A fee swap does not use `has_enough_reserve_validator_token` (an empty pool with `amount_out == 0` is accepted) and does not read the reservation.
- The only log the hooks add is the fee-token `Transfer` above (reward accounting and the spending-limit refund emit nothing); it is appended after the transaction's execution logs and is kept when execution reverted. The pre hook adds no log.

## 8. TIP-1060 storage-credit interaction (from T7)

Before T7 there are no storage credits and nothing in this section has an effect.

- **Hooks.** `collectFeePreTx` and `collectFeePostTx` run with TIP-1060 accounting disabled (Section 7.1). Which slots the handler then marks as non-creditable for the transaction (the fee payer's fee-token balance slot and, for a keychain-signed transaction whose fee payer is the sender, the key's spending-limit `remaining` slot) is specified in [06-transactions-and-fees.md](../06-transactions-and-fees.md) and [account-keychain.md](account-keychain.md).
- **disable_storage_credit_minting().** Called by `distributeFees` (first, before reading `collectedFees`) and by `rebalanceSwap` (after the validator-token pull, before the user-token transfer). From that point to the end of the current FeeManager precompile invocation, including all TIP-20, TIP-403, AccountKeychain and ReceivePolicyGuard logic it runs as direct calls, a nonzero→zero SSTORE does **not** mint a storage credit. All other TIP-1060 rules (charging for zero→nonzero creation, consuming credits, transient mode and budget) still apply. The setting does not outlive the invocation: the next precompile call starts with minting enabled. In `distributeFees` this covers zeroing `collectedFees` and clearing FeeManager's token-balance slot; in `rebalanceSwap` it covers clearing FeeManager's user-token balance slot (created for free by pre-collection), but not the validator-token pull before it.
- `mint`, `burn`, `setUserToken` and `setValidatorToken` do not disable minting: a nonzero→zero SSTORE in them mints credits normally.

## 9. Per-fork summary

| Fork | Change in this chapter |
|---|---|
| Genesis / T0 | Precompile and full ABI live. Pre hook authorizes fee payer as sender **and** FeeManager as recipient. Direct route only, no reservation. |
| T1C | Direct-route reservation (Section 7.4); `burn` and `rebalanceSwap` reservation checks; post-hook refund restores the access-key spending limit. |
| T2 | Pre-T8 pre-hook authorization short-circuits: a failing sender check skips the FeeManager recipient lookup. |
| T3 | `setUserToken` with the already-stored token is a no-op (no SSTORE, no event). |
| T5 | Two-hop route through `userToken.quoteToken()` with reservation of both legs and `twoHopIntermediate`; `systemTransferFrom` requires the caller on the Implicit Approval List (FeeManager is listed). |
| T7 | TIP-1060 storage credits: hooks run without accounting; minting disabled in `distributeFees` and `rebalanceSwap` (Section 8). |
| T8 | TIP-1042 authorization: pre hook checks only the fee payer as sender; `mint` checks `(msg.sender sender, FeeManager recipient, to recipient)` on userToken then `to` recipient on validatorToken; `burn` checks `msg.sender` as sender on userToken then validatorToken. Pools created before T8 stay routable. |
| T1, T1A, T1B, T4, T6, T9–T13 | No change to this precompile's own logic. Changes reached through TIP-20, TIP-403, the framework (input gas, ABI strictness at T11/T12, static-call halting at T12) and fee-token resolution (T13 ordered fallback) are specified in their chapters. |

## 10. Invariants (informative)

For every pool `id = pool_id(u, v)` and at every transaction boundary:

1. `reserveUserToken` and `reserveValidatorToken` fit in 128 bits.
2. `totalSupply[id] = MIN_LIQUIDITY × (number of initializations) + Σ_holders liquidityBalances[id][h]`.
3. `balanceOf_T(FEE_MANAGER) ≥ Σ_pools reserves in T + Σ_validators collectedFees[·][T]` for every token T.
4. A pool's `reserveUserToken` only increases through fee swaps and only decreases through `burn` and `rebalanceSwap`.
5. From T1C, a transaction whose pre hook succeeded never fails in its post hook for lack of reserves.
