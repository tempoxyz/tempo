# 06 — Transactions and fees

This chapter specifies how a single transaction is validated, charged, executed and settled, for every transaction type a Tempo block may contain, from mainnet genesis through T13. It is normative for block validity: a client that follows it computes the same state, receipts and gas as every other conforming client.

Block-level concerns are out of scope here and live in [05-block-execution.md](05-block-execution.md): the block-section and lane state machine, the pre-T4 subblock-metadata system transaction, pre/post-block system calls, the per-block gas-limit accounting, the block beneficiary, opcode-level gas (SSTORE set/clear costs and refunds, code deposit, CREATE opcode), and the base fee. Transaction encodings, hashes and signing payloads are in [02-encoding.md](02-encoding.md); signature formats, recovery and the fee-payer signing domain are in [03-signatures.md](03-signatures.md). Precompile internals are in the precompile chapters linked where used.

## 1. Conventions

### 1.1 Fork predicate

"From F:" means the rule applies to a transaction executed in a block whose `header.timestamp >= activation_time(F)`, using the fork predicate defined in [01-chain-and-forks.md](01-chain-and-forks.md). "Before F:" is its negation. Every Tempo fork maps to the Ethereum Osaka rule set (all Ethereum forks through Osaka are active from genesis), so every EIP through Osaka applies unless this chapter overrides it. Ethereum rules are referenced by EIP number and by the Osaka execution-specs; §1.6 lists every Tempo deviation from them.

On mainnet (chain id 4217) T0 is active at genesis and T1A activates together with T1; rules stated as "Before T0" apply only to Moderato (chain id 42431) and are given for completeness only.

### 1.2 Terms

This chapter is read together with its sibling chapters; the terms below are defined fully there and summarized here.

- **Forks.** Tempo's hardforks, in activation order: Genesis (Moderato only), T0, T1, T1A, T1B, T1C, T2, T3, …, T13. Each activates at a timestamp per chain ([01-chain-and-forks.md](01-chain-and-forks.md)). Moderato is Tempo's public testnet (chain id 42431).
- **TIP-20 token.** Tempo's native fungible-token precompile, with 6 decimals, an ISO-like `currency` string, pause state and TIP-403 transfer policies; every TIP-20 address starts with `TIP20_PREFIX` ([precompiles/tip20.md](precompiles/tip20.md)). pathUSD (`PATH_USD`) and OUSD (`OUSD`) are USD TIP-20 tokens.
- **Fee token.** The USD TIP-20 token a transaction's fee is paid in (§6). Fees are pre-collected into the **FeeManager** precompile (`FEE_MANAGER`) and converted to the block proposer's preferred token through the **fee AMM**, a set of constant-rate pools inside the FeeManager; a conversion route (direct pool or, from T5, two pools through an intermediate token) must have liquidity ([precompiles/fee-manager.md](precompiles/fee-manager.md)).
- **TIP-403 policy.** A per-token transfer-authorization policy (allow/deny lists) that TIP-20 enforces on senders and recipients ([precompiles/tip403.md](precompiles/tip403.md)).
- **AccountKeychain, root key, access key.** The AccountKeychain precompile (`ACCOUNT_KEYCHAIN`) stores, per account, secondary signing keys ("access keys") with an expiry, optional per-token spending limits and optional call scopes; from T6 an access key may be an admin key. The account's own key is the root key. A `0x76` transaction signed by an access key carries a **Keychain signature**; a `key_authorization` field registers a new access key ([precompiles/account-keychain.md](precompiles/account-keychain.md)).
- **Nonce keys.** A `0x76` transaction selects its replay protection by `nonce_key`: 0 is the ordinary account nonce ("protocol nonce"); other values are independent sequential "2D nonces" stored in the **NonceManager** precompile (`NONCE_MANAGER`); from T1, `EXPIRING_NONCE_KEY` selects an "expiring nonce": no sequence, but a replay set bounded by `valid_before` (§4.8).
- **Subblocks and lanes.** Block-level structures of [05-block-execution.md](05-block-execution.md); this chapter only rejects subblock nonce keys (§4.2).
- **State gas.** The EIP-8037 split of gas into execution and state components; it is disabled for every fork in scope, so all state-gas amounts are 0.

### 1.3 Outcomes

Every check in this chapter ends a transaction in exactly one of two ways:

- **Invalid.** The transaction MUST NOT be included. If a block contains an invalid transaction, the block is invalid. No state change of the transaction survives (the state is as if the transaction were absent).
- **Failed** (included, receipt status 0). The transaction is included, its fee is charged for the gas it used, and only the state changes this chapter lists as surviving remain.

A transaction that completes all calls successfully is **successful** (receipt status 1).

Where this chapter lists checks in order, the order is normative only where an earlier step changes state a later step reads (for example the sender nonce bump before EIP-7702 authorization processing, or fee collection before key authorization). Among purely stateless checks, any order yields the same verdict.

### 1.4 Constants

| Name | Value |
|---|---|
| `TEMPO_TX_TYPE` | `0x76` |
| `EXPIRING_NONCE_KEY` | `2**256 - 1` (`uint256.max`) |
| `SUBBLOCK_NONCE_KEY_PREFIX` | `0x5b` (most significant byte of `nonce_key`) |
| `GAS_PRICE_SCALE` | `10**12` (attodollars per gas × gas → microdollar TIP-20 base units) |
| `PATH_USD` | `0x20C0000000000000000000000000000000000000` |
| `OUSD` | `0x20c0000000000000000000006a37da5c996874be` |
| `TIP20_PREFIX` | the 12 bytes `0x20C000000000000000000000` |
| `FEE_MANAGER` | `0xfeec000000000000000000000000000000000000` |
| `STABLECOIN_DEX` | `0xdec0000000000000000000000000000000000000` |
| `NONCE_MANAGER` | `0x4E4F4E4345000000000000000000000000000000` |
| `ACCOUNT_KEYCHAIN` | `0xAAAAAAAA00000000000000000000000000000000` |
| `TX_GAS_LIMIT_CAP` | before T1A: `16_777_216` (EIP-7825 `2**24`); from T1A: `30_000_000` |
| `EXPIRING_NONCE_GAS` | `13_000` (`2*2_100 + 100 + 3*2_900`) |
| `KEYCHAIN_VALIDATION_GAS` | `3_000` (`2_100 + 900`) |
| `SECP256K1_VERIFY_GAS` / `P256_VERIFY_GAS` / `WEBAUTHN_VERIFY_GAS` | `3_000` / `8_000` / `8_000` |
| `KEY_AUTH_BASE_GAS` / `KEY_AUTH_PER_LIMIT_GAS` | `27_000` / `22_000` (before T1B) |
| `KEY_AUTH_BUFFER` / `KEY_AUTH_EXTRA_EVENT_BUFFER` | `2_000` / `1_500` (from T1B) |
| `STORAGE_CREDIT_VALUE` | `245_000` (TIP-1060: `250_000 - 5_000`) |
| `EXPIRING_NONCE_MAX_EXPIRY_SECS` | before T11: `30`; from T11: `300` |
| `EXPIRING_NONCE_SET_CAPACITY` | before T11: `300_000`; from T11: `3_000_000` |

> **Resolved conflict C-TXF-03**: TIP-1010 calls the previous transaction gas cap 16,000,000 and dates the 30M cap to T1; the code uses EIP-7825's 16,777,216 before T1A and 30,000,000 from T1A. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-03).

### 1.5 Transaction-level gas parameters

These are the transaction-level entries of the gas schedule (the full schedule, including opcode costs, is in [05-block-execution.md](05-block-execution.md)). EIP-8037/TIP-1016 state gas is disabled at every fork in scope: every "state gas" quantity is 0, the state-gas reservoir is always 0, and `execution_gas = gas_limit - intrinsic_gas`.

| Parameter | Before T1 | T1 – T6 | From T7 |
|---|---|---|---|
| `TX_BASE` | 21,000 | 21,000 | 21,000 |
| `TX_DATA_TOKEN_COST` (per token; zero byte = 1 token, non-zero byte = 4 tokens) | 4 | 4 | 4 |
| `TX_CREATE_COST` (top-level CREATE, also the 0x76 per-CREATE-call cost) | 32,000 | 500,000 | 500,000 |
| `INITCODE_WORD_COST` (EIP-3860, per 32-byte word, rounded up) | 2 | 2 | 2 |
| `NEW_ACCOUNT_COST` | 25,000 | 250,000 | 250,000 |
| `PER_AUTH_COST` (EIP-7702 `PER_EMPTY_ACCOUNT_COST`) | 25,000 | 12,500 | 12,500 |
| `AUTH_REFUND` (EIP-7702 refund for an existing authority) | 12,500 | 0 | 0 |
| `ACCESS_LIST_ADDRESS_COST` / `ACCESS_LIST_STORAGE_KEY_COST` | 2,400 / 1,900 | same | same |
| `COLD_ACCOUNT_ACCESS_COST` / `COLD_SLOAD_COST` / `WARM_STORAGE_READ_COST` | 2,600 / 2,100 / 100 | same | same |
| `SSTORE_SET_COST` (clean zero → non-zero SSTORE, excluding the 100-gas static part; `SstoreSetWithoutLoadCost` in [05](05-block-execution.md#17-gas-schedule-per-fork), `SSTORE_SET` in [precompiles/00-framework.md](precompiles/00-framework.md#71-gas-parameters)) | 19,900 | 250,000 | 5,000 |
| `FLOOR_BASE` / `FLOOR_COST_PER_TOKEN` (EIP-7623) | 21,000 / 10 | same | same |
| `MAX_REFUND_QUOTIENT` | 5 | 5 | 1 |

The EIP-7623 floor counts calldata tokens only (Osaka: access-list bytes add nothing to the floor). Calldata tokens are `tokens(data) = zero_bytes(data) + 4 * nonzero_bytes(data)`.

### 1.6 Ethereum base and Tempo deviations

Transactions of types 0, 1, 2 and 4 are validated and processed as in the Osaka fork of [`ethereum/execution-specs`](https://github.com/ethereum/execution-specs) (`validate_transaction`, `check_transaction` and `process_transaction`), including the EIPs that fork contains. Type `0x76` is specified by this chapter (§4); its calls and contract creations execute as Osaka message calls and creations. Tempo's EVM changes (precompile sets, opcode overrides, the per-fork gas schedule, refund finalization) are in [05-block-execution.md](05-block-execution.md) §1.

Tempo transaction processing deviates from Osaka only as follows:

1. **No blob transactions.** Type 3 does not exist, so blob gas and the blob fee are always 0 (§2).
2. **No native value.** A non-zero top-level `value` makes the transaction invalid (§2.1 item 1).
3. **No native gas payment.** The sender balance check, the up-front gas purchase, the refund of unused gas, the priority-fee payment to the beneficiary and the base-fee burn are not performed. The fee is paid in a TIP-20 fee token by the fee payer (§5–§7), and every fee-token failure makes the transaction invalid.
4. **Intrinsic gas.** The intrinsic-gas parameters change per fork (§1.5), and from T1 a new-account charge is added (§3.1).
5. **EIP-7702 costs.** From T1 the per-authorization cost is 12,500 and the refund for an existing authority is 0 (§1.5).
6. **Transaction gas limit cap.** The EIP-7825 cap is 30,000,000 from T1A (§1.4).
7. **Refunds.** From T7 the refund quotient is 1 and TIP-1060 storage-credit refunds are added. A net-negative refund counter refunds the full cap (§7.3).
8. **Nonce before fees (types 0, 1, 2, 4).** For these types the sender nonce is incremented before fee resolution and fee collection (§3.2). Type `0x76` follows its own order (§4.1): the fee context is resolved before the nonce is processed.
9. **Receipt logs.** The fee `Transfer` log is appended after the execution logs (§9).

## 2. Transaction types

A Tempo block MAY contain transactions of EIP-2718 types 0 (legacy), 1 (EIP-2930), 2 (EIP-1559), 4 (EIP-7702) and `0x76` (Tempo transaction). Type 3 (EIP-4844 blob) transactions do not exist on Tempo (they are not part of the Tempo envelope, [02-encoding.md](02-encoding.md)); blob gas used is always 0. A legacy transaction that is a Tempo system transaction (before T4 only) is processed as specified in [05-block-execution.md](05-block-execution.md), not by this chapter.

### 2.1 Rules common to all types

1. **No native value.** Tempo has no native token: every genesis balance is 0 and nothing mints native balance. A transaction whose top-level `value` is non-zero is invalid (for types 0/1/2/4); a `0x76` transaction with any call whose `value` is non-zero is invalid. The Ethereum upfront balance check and the native gas purchase/refund/coinbase payment do not exist: gas is paid in a TIP-20 fee token (§6–§7), the base fee is not burned, and the beneficiary receives no native balance. Consequently `BALANCE`/`SELFBALANCE` return 0 and inner calls carrying value fail as in Ethereum with insufficient balance.
2. **Gas limit caps.** `gas_limit > TX_GAS_LIMIT_CAP` is invalid. `gas_limit > header.gas_limit` is invalid. (Lane and cumulative block-gas checks are in [05-block-execution.md](05-block-execution.md).)
3. **Fee fields.** For types 2, 4 and `0x76`: `max_priority_fee_per_gas > max_fee_per_gas` is invalid. For every type, with `price = effective_gas_price(tx, header.base_fee_per_gas)` (§7.1), `price < base_fee` is invalid.
4. **Chain id.** Types 1, 2, 4 and `0x76` MUST carry `chain_id == chain.id`, else invalid. A legacy transaction MAY omit the chain id (pre-EIP-155 signature); if present it MUST equal `chain.id`.
5. **Nonce overflow.** `nonce == 2**64 - 1` is invalid, except for a `0x76` expiring-nonce transaction from T1 (§4.8.3).
6. **Initcode size.** A top-level CREATE (type 0/1/2 with empty `to`, or a `0x76` CREATE call) whose initcode exceeds 49,152 bytes (EIP-3860) is invalid.
7. **Sender with code (EIP-3607).** If the sender account has non-empty code that is not an EIP-7702 delegation designator, the transaction is invalid.
8. **Intrinsic gas and floor.** `gas_limit < intrinsic_gas` or `gas_limit < floor_gas` is invalid (formulas per type below).

## 3. Types 0, 1, 2 and 4

These follow the Osaka execution-specs for validation, intrinsic gas, nonce handling, EIP-7702 authorization processing and execution, with the changes below.

### 3.1 Intrinsic gas

`intrinsic_gas` is the Osaka intrinsic gas computed with the parameters of §1.5 (so a top-level CREATE costs `TX_BASE + TX_CREATE_COST + INITCODE_WORD_COST * ceil(len/32)`, and a type-4 transaction pays `PER_AUTH_COST` per authorization tuple), plus, from T1 (TIP-1000):

```python
def tempo_t1_extra_intrinsic(tx) -> int:
    new_accounts = (1 if tx.nonce == 0 else 0)
    if tx.type == 4:
        new_accounts += sum(1 for auth in tx.authorization_list if auth.nonce == 0)
    return new_accounts * NEW_ACCOUNT_COST    # 250_000 each
```

`floor_gas = FLOOR_BASE + FLOOR_COST_PER_TOKEN * tokens(tx.data)` (EIP-7623).

> **Resolved conflict C-TXF-02**: TIP-1000 also charges +250,000 for each EIP-7702 authorization that moves an account from no delegation to delegation; the code charges no such amount (for type 4 and for 0x76 authorizations alike). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-02).

### 3.2 Processing order

The fee steps (`resolve_fee_context`, §6.1, and `collect_fee_pre_tx`, §7.2) are shared with type `0x76` and specified once, later in this chapter.

```python
def prepare_ethereum_tx(tx, sender):
    check_common_rules(tx)                 # §2.1 items 1-6, 8
    # §2.1 item 7, then the Osaka nonce check:
    if sender.nonce != tx.nonce: invalid()
    sender.nonce += 1                      # bumped here for CALL and CREATE alike
    warm(sender); warm(header.beneficiary); warm(tx.to if call); warm(active Ethereum precompiles)   # Tempo precompiles are not pre-warmed
    warm(access_list)                      # types 1, 2, 4
    fee = resolve_fee_context(tx)          # §6, may be invalid
    collect_fee_pre_tx(fee)                # §7.2, may be invalid
```

`warm(active Ethereum precompiles)` warms only the base Ethereum precompile addresses active at the block's fork ([precompiles/00-framework.md §2.1](precompiles/00-framework.md#21-base-ethereum-precompiles)); no Tempo precompile address is pre-warmed (§4.7).

Then the transaction executes as in Osaka: for type 4, the authorization list is applied first (EIP-7702: tuples with a wrong chain id, `nonce == 2**64-1`, an unrecoverable signature, an authority with non-delegation code or a nonce mismatch are skipped; a valid tuple installs `0xef0100 || address`, or clears the code when `address == 0`, and increments the authority nonce; before T1 a tuple whose authority already existed adds `AUTH_REFUND` to the refund counter). Delegations survive a failed execution. The message call or creation then runs with `gas_limit - intrinsic_gas` gas. Settlement is §7.3.

A type-4 transaction with an empty authorization list, or with a CREATE destination, is invalid (EIP-7702).

Fee-related failures (no resolvable or invalid fee token, insufficient fee-token balance, insufficient fee AMM liquidity, paused fee token, TIP-403 sender policy) make the transaction invalid; they never produce a failed receipt.

## 4. Type 0x76 (Tempo transaction)

Field definitions and encodings are in [02-encoding.md](02-encoding.md). The relevant fields are: `chain_id`, `max_priority_fee_per_gas`, `max_fee_per_gas`, `gas_limit`, `calls` (each `{to: Address | Create, value, input}`), `access_list`, `nonce_key` (uint256), `nonce` (uint64), `valid_before` / `valid_after` (optional non-zero uint64 seconds), `fee_token` (optional address), `fee_payer_signature` (optional secp256k1 signature), `key_authorization` (optional signed key authorization) and `aa_authorization_list` (EIP-7702-style authorizations signed with Tempo signatures). `sender` is the address recovered from the transaction signature ([03-signatures.md](03-signatures.md)); for a Keychain signature it is the signature's `user_address` after the inner signature verifies, and `access_key` is the key id the Keychain signature recovers (`None` for a non-Keychain signature).

### 4.1 Pipeline overview

```python
def process_tempo_tx(tx):
    # --- stateless validation (any failure: invalid) ---
    check_structure(tx)                    # §4.2
    check_key_authorization_stateless(tx)  # §4.3
    fee_payer = resolve_fee_payer(tx)      # §5
    check_fee_and_gas_fields(tx)           # §4.4
    check_time_window(tx)                  # §4.5
    intrinsic, floor = intrinsic_gas(tx)   # §4.6 (reads sender account for one term)
    # --- stateful pre-execution (any failure: invalid) ---
    warm_accounts(tx)                      # §4.7
    fee = resolve_fee_context(tx)          # §6
    create_nonce = apply_nonce(tx)         # §4.8   (2D: emits NonceIncremented)
    keychain = prepare_keychain(tx, fee)   # §4.9
    collect_fee_pre_tx(fee, keychain)      # §7.2
    key_auth_gas = apply_key_authorization(tx, fee, keychain)  # §4.10
    apply_tempo_authorization_list(tx)     # §4.11
    if key_auth_gas is OUT_OF_GAS:         # T1/T1A only, §4.10.2
        return settle(failed_out_of_gas)   # failed; batch not executed
    # --- execution (failures here: failed, not invalid) ---
    result = execute_batch(tx, create_nonce)   # §4.12
    return settle(result)                  # §7.3, §8
```

Everything before `execute_batch` that changes state (nonce consumption, fee pre-collection, key authorization, EIP-7702 delegations) is outside the batch checkpoint and survives a failed batch (§4.13).

### 4.2 Structure checks

In this order; each failure makes the transaction invalid:

1. `nonce_key`'s most significant byte equals `SUBBLOCK_NONCE_KEY_PREFIX` (`0x5b`) (all forks; subblock transactions are never valid in a block).
2. Any `aa_authorization_list` entry's signature is, or wraps, a configurable-account signature (all forks). More generally, every configurable-account construct (configurable-account transaction signatures, roles or grants, TIP-1114) is introduced by T14 and MUST be rejected as invalid at every fork in scope ([03-signatures.md](03-signatures.md)).
3. `calls` validation:
   - `calls` is empty;
   - any call other than the first is a CREATE;
   - the first call is a CREATE and `aa_authorization_list` is non-empty.
4. Keychain signature version, checked for the transaction signature and for every `aa_authorization_list` signature: before T1C a V2 Keychain signature (type byte `0x04`) is invalid; from T1C a legacy V1 Keychain signature (type byte `0x03`) is invalid.
5. Key-authorization stateless checks (§4.3), if `key_authorization` is present.
6. From T3: the transaction signature is a Keychain signature and the first call is a CREATE.
7. Any call has `value != 0`.
8. Fee payer: `fee_payer_signature` is present and secp256k1 recovery over the fee-payer signing hash fails ([03-signatures.md](03-signatures.md)). From T2: `fee_payer_signature` is present and the recovered fee payer equals `sender` (self-sponsorship).

### 4.3 Key-authorization stateless checks

Let `ka = tx.key_authorization`, `same_tx = (access_key == ka.key_id)` and `signer = authorizing_account(ka)` (secp256k1/P256/WebAuthn recovery over `keccak256(rlp(ka.authorization))`, [03-signatures.md](03-signatures.md)). Each failure is invalid; in this order:

1. Before T6: `access_key` is set and `not same_tx` (an access key cannot authorize another key).
2. From T3: `same_tx` and `ka.key_type` differs from the Keychain inner signature's type.
3. Before T6: `ka.is_admin` is true or `ka.account` is present.
4. From T6: `ka.account` is present and differs from `sender`.
5. `ka.is_admin` is true and any of `expiry`, `limits`, `allowed_calls` is present.
6. Recovery of `signer` fails. Before T6: `signer != sender`.
7. Chain id: before T1C, `ka.chain_id ∉ {0, chain.id}` (0 is a wildcard); from T1C, `ka.chain_id != chain.id`.
8. Before T5: `ka.witness` is present.
9. Before T3: any `limits` entry has `period != 0`, or `allowed_calls` is present (even `Some([])`).
10. From T6:
    - `signer != sender` and `ka.account` is absent;
    - `signer == sender`, `access_key` is set and `not same_tx` (a root-signed authorization must ride on a root-signed transaction);
    - `signer != sender` and (the transaction signature is not a Keychain signature, or `access_key != signer`, or `ka.signature`'s type differs from the Keychain inner signature's type).

A further stateful check (§4.9) requires, from T6, that a non-root `signer` is an active admin key of `sender`.

### 4.4 Fee and gas field checks

With `price = min(max_fee_per_gas, base_fee + max_priority_fee_per_gas)`; each failure is invalid:

1. `max_priority_fee_per_gas > max_fee_per_gas`.
2. `price < base_fee`.
3. `chain_id != chain.id`.
4. `gas_limit > TX_GAS_LIMIT_CAP`.
5. `gas_limit > header.gas_limit`.
6. `nonce == 2**64 - 1`, unless (from T1) `nonce_key == EXPIRING_NONCE_KEY`.
7. A CREATE call's `input` is longer than 49,152 bytes.

### 4.5 Validity window

With `now = header.timestamp` (seconds):

- `valid_after` present and `now < valid_after`: invalid.
- `valid_before` present and `now >= valid_before`: invalid.

A transaction is therefore valid only for `valid_after <= now < valid_before` (each bound only when present). Expiring-nonce transactions additionally bound `valid_before` from above (§4.8.3).

### 4.6 Intrinsic gas

```python
def sig_intrinsic_gas(sig) -> int:
    # Gas a signature adds on top of TX_BASE (which already covers one secp256k1 recovery).
    if sig is Secp256k1: return 0
    if sig is P256:      return P256_VERIFY_GAS - SECP256K1_VERIFY_GAS            # 5_000
    if sig is WebAuthn:  return WEBAUTHN_VERIFY_GAS - SECP256K1_VERIFY_GAS \
                                + 4 * tokens(sig.webauthn_data)                  # 5_000 + ...
    if sig is Keychain:  return sig_intrinsic_gas(sig.inner) + KEYCHAIN_VALIDATION_GAS  # + 3_000

def sig_full_gas(sig) -> int:
    # Full verification cost, used for the key-authorization signature.
    if sig is Secp256k1: return SECP256K1_VERIFY_GAS                              # 3_000
    if sig is P256:      return P256_VERIFY_GAS                                   # 8_000
    if sig is WebAuthn:  return WEBAUTHN_VERIFY_GAS + 4 * tokens(sig.webauthn_data)

def intrinsic_gas(tx, fork, sender_account) -> (int, int):
    g = TX_BASE
    g += sig_intrinsic_gas(tx.signature)
    g += COLD_ACCOUNT_ACCESS_COST * (len(tx.calls) - 1)          # 2_600 per extra call
    for auth in tx.aa_authorization_list:
        g += PER_AUTH_COST + sig_intrinsic_gas(auth.signature)
        if fork >= T1 and auth.nonce == 0:
            g += NEW_ACCOUNT_COST                                 # 250_000
    if tx.key_authorization is not None:
        g += key_authorization_gas(tx.key_authorization, fork)    # §4.6.1
    data_tokens = 0
    for call in tx.calls:
        data_tokens += tokens(call.input)
        if call.to is Create:
            g += TX_CREATE_COST + INITCODE_WORD_COST * ceil(len(call.input) / 32)
    g += TX_DATA_TOKEN_COST * data_tokens
    g += ACCESS_LIST_ADDRESS_COST * len(tx.access_list) \
       + ACCESS_LIST_STORAGE_KEY_COST * total_storage_keys(tx.access_list)
    floor = FLOOR_BASE + FLOOR_COST_PER_TOKEN * data_tokens
    g += nonce_gas(tx, fork)                                      # §4.6.2
    if tx.nonce_key != 0 and tx.calls[0].to is Create \
       and (sender_account is None or sender_account.nonce == 0):
        g += NEW_ACCOUNT_COST            # 25_000 before T1, 250_000 from T1
    return g, floor
```

`gas_limit < g` or `gas_limit < floor` is invalid. `sender_account` is the sender's account in the state before the transaction. `execution_gas = gas_limit - g` (from T1 and before T1B, further reduced by the metered key-authorization gas, §4.10.2).

Before T0 (Moderato only): `nonce_gas` is added after the `gas_limit >= g` check, and if `g > gas_limit` as a result the batch executes with `2**64 - 1` gas and settlement still uses `gas_limit`; the CREATE-with-2D-nonce term is always included in the check.

> **Resolved conflict C-TXF-01**: the transaction spec prices WebAuthn as 26,000 plus calldata gas of `clientDataJSON`; the code charges `5_000 + 4 * tokens(webauthn_data)` on top of the base, where `webauthn_data = authenticatorData || clientDataJSON`. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-01).

#### 4.6.1 Key-authorization gas

```python
def key_authorization_gas(ska, fork) -> int:
    ka = ska.authorization
    sig = sig_full_gas(ska.signature)
    n = len(ka.limits) if ka.limits is not None else 0
    if fork < T1B:
        return KEY_AUTH_BASE_GAS + sig + KEY_AUTH_PER_LIMIT_GAS * n     # 27_000 + sig + 22_000*n
    sload = COLD_SLOAD_COST                                         # 2_100: one cold SLOAD
    limit_slots = 2 * n if fork >= T3 else n
    sstores = 1 + limit_slots
    if fork >= T3:
        sstores += call_scope_storage_slots(ka, fork)
    sstore = SSTORE_SET_COST + (STORAGE_CREDIT_VALUE if fork >= T7 else 0)   # 250_000 at every fork from T1B
    g = sig + sload + sstore * sstores + KEY_AUTH_BUFFER
    if ka.witness is not None:                # only reachable from T5
        g += sload + KEY_AUTH_EXTRA_EVENT_BUFFER
    if fork >= T6 and ka.is_admin:
        g += KEY_AUTH_EXTRA_EVENT_BUFFER
    if fork >= T4:
        g += call_scope_extra_gas(ka)
    return g

def call_scope_storage_slots(ka, fork) -> int:
    if ka.allowed_calls is None: return 0
    scopes = ka.allowed_calls
    if len(scopes) == 0: return 1
    S = len(scopes)                                     # targets
    K = sum(len(s.selector_rules) for s in scopes)      # selector rules
    C = sum(1 for s in scopes for r in s.selector_rules if len(r.recipients) > 0)
    W = sum(len(r.recipients) for s in scopes for r in s.selector_rules)
    if fork >= T4:
        P = sum(1 for s in scopes if len(s.selector_rules) > 0)   # targets that persist selectors
        return 1 + 2 * S + 1 + 2 * K + P + C + 2 * W
    return 1 + 3 * S + 3 * K + C + 2 * W                # T3

def call_scope_extra_gas(ka) -> int:                    # from T4
    if ka.allowed_calls is None: return 5_000
    S, K, W = (as above)
    return 5_000 + 7_000 * S + 7_000 * K + 5_000 * W
```

Before T1B the key-authorization precompile write is not covered by this amount alone: at T1 and T1A it is additionally metered (§4.10.2); before T1 it is free.

> **Resolved conflict C-TXF-04**: TIP-1011 gives the scope slot count `1 + 3S + 3K + C + 2W` and frames the rounded overhead as optional and scope-only; from T4 the code uses `1 + 2S + 1 + 2K + P + C + 2W` and always adds the 5,000 base, also when `allowed_calls` is absent. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-04).

#### 4.6.2 Nonce gas

```python
def nonce_gas(tx, fork) -> int:
    if fork >= T1 and tx.nonce_key == EXPIRING_NONCE_KEY:
        return EXPIRING_NONCE_GAS                       # 13_000
    if fork >= T1 and tx.nonce == 0:
        return NEW_ACCOUNT_COST                         # 250_000, any nonce_key (incl. 0)
    if tx.nonce_key != 0:
        if tx.nonce == 0:
            return 22_300 if fork >= T2 else 22_100     # new 2D key (cold SLOAD + SSTORE set [+ 2 warm reads])
        return 5_200 if fork >= T2 else 5_000           # existing 2D key (cold SLOAD + SSTORE reset [+ 2 warm reads])
    return 0
```

Because a new 2D key always has `nonce == 0`, the new-key amounts apply only before T1; from T1 a new key pays 250,000.

> **Resolved conflict C-TXF-08**: TIP-1000 charges the 250,000 account-creation gas to Tempo transactions "with any `nonce_key` and `nonce == 0`"; the code charges an expiring-nonce transaction (`nonce_key == uint256.max`) only `EXPIRING_NONCE_GAS`. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-08).

### 4.7 Warming

Before fee resolution, the following are added to the EIP-2929 warm set (no gas charged): `sender`; `header.beneficiary` (EIP-3651); `calls[0].to` if it is a call; the active Ethereum (base) precompile addresses ([precompiles/00-framework.md §2.1](precompiles/00-framework.md#21-base-ethereum-precompiles); Tempo precompile addresses are not pre-warmed); every access-list address and storage key. Other call targets are warmed immediately before their call executes (§4.12); the intrinsic `2_600` per extra call pays for that.

### 4.8 Nonce processing

```python
def apply_nonce(tx, fork) -> int:            # returns create_nonce
    acct = state.account(sender)
    if acct.code is non-empty and not an EIP-7702 delegation designator:
        invalid()                            # EIP-3607
    touch(acct)
    protocol_nonce = acct.nonce
    if tx.nonce_key == 0:                    # §4.8.1
        if tx.nonce != protocol_nonce: invalid()
        if tx.calls[0].to is not Create:
            acct.nonce += 1                  # a CREATE-first tx bumps in the batch, §4.12
        return protocol_nonce
    if fork >= T1 and tx.nonce_key == EXPIRING_NONCE_KEY:   # §4.8.3
        expiring_nonce_check_and_mark(tx, fork)
        return protocol_nonce
    two_d_nonce(tx)                          # §4.8.2
    return protocol_nonce
```

The protocol nonce is never compared for 2D or expiring transactions. Nonce state written here is written by the protocol, is not charged beyond the intrinsic nonce gas, and survives a failed batch.

`touch(acct)` marks the sender as touched in the sense of EIP-161 for this transaction, whether or not the account exists. At the end of the transaction, as in Osaka, every touched account that is empty (nonce 0, zero balance, empty code) is deleted from the state, and a touched account that does not exist is not created. Native balances are always zero on Tempo ([05-block-execution.md](05-block-execution.md#14-no-native-token)), so a sender with nonce 0 and no code that sends a 2D-nonce or expiring-nonce transaction, which does not bump its protocol nonce, is absent from the post-transaction state, unless something else in the transaction gave it a nonce or code (such as a self-authorization in `aa_authorization_list` or a CREATE call). Its nonce-key and replay-record state lives in the NonceManager's storage and is kept.

#### 4.8.1 Protocol nonce (`nonce_key == 0`)

`tx.nonce` MUST equal the sender's account nonce. For a CALL-first transaction the nonce is incremented here, before fee collection and before EIP-7702 authorizations are applied (so a self-authorization in the same transaction MUST carry `tx.nonce + 1`). For a CREATE-first transaction the nonce is incremented by the CREATE in §4.12, and is consumed even if the batch fails.

#### 4.8.2 2D nonces (`nonce_key ∉ {0, EXPIRING_NONCE_KEY}`, or `nonce_key == EXPIRING_NONCE_KEY` before T1)

```python
def two_d_nonce(tx):
    current = NonceManager.nonces[sender][tx.nonce_key]       # 0 if never used
    if tx.nonce != current: invalid()
    if current == 2**64 - 1: invalid()                        # NonceOverflow
    NonceManager.nonces[sender][tx.nonce_key] = current + 1
    emit NonceManager.NonceIncremented(account=sender, nonceKey=tx.nonce_key, newNonce=current + 1)
```

The NonceManager precompile's storage layout and ABI are in [precompiles/account-keychain.md](precompiles/account-keychain.md). Keys whose most significant byte is `0x5b` never reach this step (§4.2). Before T1, `nonce_key == uint256.max` is an ordinary 2D key.

#### 4.8.3 Expiring nonces (from T1; TIP-1009, TIP-1093, TIP-1106)

```python
def expiring_nonce_check_and_mark(tx, fork):
    if fork < T12 and tx.nonce != 0: invalid()       # from T12 any uint64 is an opaque discriminator
    if tx.valid_before is None: invalid()
    if fork >= T1B:
        h = keccak256(encode_for_signing(tx) + sender)   # 20-byte sender appended
    else:
        h = tx_hash(tx)                                   # the signed transaction hash
    now = header.timestamp
    vb = tx.valid_before
    if vb <= now or vb > now + EXPIRING_NONCE_MAX_EXPIRY_SECS: invalid()
    seen = NonceManager.expiring_nonce_seen
    ring = NonceManager.expiring_nonce_ring
    if seen[h] != 0 and seen[h] > now: invalid()          # replay
    ptr = NonceManager.expiring_nonce_ring_ptr
    old = ring[ptr]
    if old != 0:
        if seen[old] != 0 and seen[old] > now: invalid()  # set full: oldest entry not expired
        seen[old] = 0
    ring[ptr] = h
    seen[h] = vb
    NonceManager.expiring_nonce_ring_ptr = 0 if ptr + 1 >= EXPIRING_NONCE_SET_CAPACITY else ptr + 1
```

`encode_for_signing` is the sender signing payload of [03-signatures.md](03-signatures.md) (it omits the fee-payer signature and, for sponsored transactions, the fee token), so from T1B a different fee-payer signature cannot replay the same sender payload. No `NonceIncremented` event is emitted, the protocol nonce is not incremented (unless the first call is a CREATE, §4.12), and the 250,000 account-creation nonce gas is never charged (§4.6.2).

At T11 the window grows from 30 to 300 seconds and the capacity from 300,000 to 3,000,000; the stored pointer and ring entries carry over unchanged, so the pointer continues from its pre-T11 value and wraps at the new capacity. At T12 the nonce-zero requirement is removed; since `nonce` is part of `encode_for_signing` and of the transaction hash, distinct nonces give distinct replay keys.

> **Resolved conflict C-TXF-05**: TIP-1009 keys replay protection on the transaction hash (invariant E1: "a transaction hash can never be executed twice"); from T1B the code keys it on `keccak256(encode_for_signing || sender)`, and TIP-1009 was not amended. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-05).

> **Resolved conflict C-TXF-06**: TIP-1106 is marked `status: Draft` with `protocolVersion: TBD`, but the code activates it at T12. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-txf-06).

### 4.9 Keychain preparation

Only when the transaction signature is a Keychain signature (otherwise the transaction key remains the root key, `0x0`, and nothing here applies). Each failure is invalid.

1. The Keychain signature's `user_address` MUST equal `sender`.
2. **Same-transaction authorize-and-use** (`key_authorization` present and `ka.key_id == access_key`): the key does not exist yet, so its inline limits are checked here. If `collected != 0` (§7.1), `fee_payer == sender` and `ka.limits` is present: let `remaining` be the `limit` of the *last* entry of `ka.limits` whose `token == fee_token`, or 0 if there is none; `collected > remaining` is invalid (`SpendingLimitExceeded`). The transaction key is not set yet.
3. **Existing key** (otherwise): the key `(sender, access_key)` MUST be authorized in the AccountKeychain, not revoked and not expired at `header.timestamp`; if `key_authorization` is present or from T1, the key's stored signature type MUST accept the inner signature's type ([precompiles/account-keychain.md](precompiles/account-keychain.md)). If `key_authorization` is present the acting key MUST be an admin key (reachable only from T6, §4.3 item 1). The AccountKeychain transaction key (transient) is then set to `access_key`; it scopes spending limits and call scopes for the rest of the transaction.
4. From T6, if `key_authorization` is present and its `signer != sender`: the acting key loaded in step 3 MUST have `key_id == signer`, a stored signature type equal to `ka.signature`'s type, and be an admin key.

Before T1, when no `key_authorization` is present, the signature type is not checked against the stored key type.

### 4.10 Key authorization

If `key_authorization` is present, after fee pre-collection (§7.2) the key is written to the AccountKeychain as the transaction's own protocol action, outside the batch checkpoint:

```python
def apply_key_authorization(tx, fee, fork):
    ka = tx.key_authorization.authorization
    cp = checkpoint()
    metered = (T1 <= fork < T1B)
    with protocol_storage(gas_limit = (gas_limit - g) if metered else UNLIMITED,
                          gas_table = METERED_TABLE if metered else normal):
        try:
            if ka.is_admin:
                AccountKeychain.authorize_admin_key(sender, ka.key_id, ka.key_type, ka.witness)
            else:
                AccountKeychain.authorize_key(sender, ka.key_id, ka.key_type,
                    expiry = ka.expiry if ka.expiry is not None else 2**64 - 1,
                    enforce_limits = ka.limits is not None,
                    limits = [(l.token, l.limit, l.period) for l in (ka.limits or [])],
                    allow_any_calls = ka.allowed_calls is None,
                    allowed_calls = ka.allowed_calls or [],
                    witness = ka.witness)
            used = gas_used if metered else 0
        except OutOfGas if metered:
            rollback(cp); used = OUT_OF_GAS
        except PrecompileError:
            invalid()                         # e.g. key exists, key revoked, expiry in the past, bad limits/scopes
    if same_tx:                               # §4.9 step 2
        AccountKeychain.transaction_key = ka.key_id
        if fee.collected != 0:
            AccountKeychain.authorize_transfer(fee.payer, fee.token, fee.collected)   # failure: invalid
    return used
```

`authorize_transfer` applies only when `fee.payer == sender`; it requires the transaction key to be an active key (after a T1/T1A out-of-gas rollback it is not, so a sender-paid same-transaction authorize-and-use transaction is then invalid with `KeyNotFound`), and for a key with enforced limits deducts `collected` from its limit for the fee token (`SpendingLimitExceeded` is invalid) and, from T3, emits `AccessKeySpend`. The AccountKeychain semantics (validation of the authorization, storage, events, limits and periods) are in [precompiles/account-keychain.md](precompiles/account-keychain.md).

#### 4.10.1 Before T1 and from T1B

The write runs without gas metering and costs nothing beyond the intrinsic key-authorization gas of §4.6.1 (before T1 that is the 27,000-based heuristic; from T1B the exact formula). A precompile error makes the transaction invalid.

#### 4.10.2 T1 and T1A (metered)

The write runs with gas limit `gas_limit - g` (`g` from §4.6, which already includes the pre-T1B heuristic) under `METERED_TABLE`. `METERED_TABLE` is the T1 gas schedule with every parameter set to 0 except `SSTORE_SET_COST = 250_000` and `WARM_STORAGE_READ_COST = 100`. Applied to the primitive costs of [precompiles/00-framework.md §7](precompiles/00-framework.md#7-gas-metering-of-primitives), it gives:

| Primitive | Cost under `METERED_TABLE` (T1/T1A) |
|---|---|
| SLOAD | 100, cold or warm (`COLD_SLOAD_EXTRA` = 0) |
| SSTORE | 250,000 when clean and effective with `original == 0` (`original == present == 0`, `new != 0`); 0 otherwise (static part, `COLD_SSTORE_EXTRA` and `SSTORE_RESET` are 0) |
| SINC, SDEC | the SLOAD and SSTORE above |
| SSTORE refunds | none (before T4 no refund is recorded, [framework §7.3](precompiles/00-framework.md#73-sstore-refunds)) |
| TLOAD, TSTORE | 100 each |
| LOG | 375 per log, whatever its topics and data (per-topic and per-byte terms are 0) |
| KECCAK | `30 + 6 × ceil(len / 32)` (constant) |
| ECRECOVER | 3,000 (constant) |
| ACCOUNT_READ | 100, cold or warm (`COLD_ACCOUNT_EXTRA` = 0) |
| WARM_CALLER_READ | 0 |
| SET_CODE | 0 (`CODE_DEPOSIT` = 0) |
| Input charge ([framework §4.1](precompiles/00-framework.md#41-input-charge-tip-1100)), duplicate-validation charge ([framework §4.2](precompiles/00-framework.md#42-duplicate-validation-charge-tip-1105)) | none (no ABI dispatch; the duplicate-validation charge is T11+) |
| TIP-1060 hook ([framework §7.4](precompiles/00-framework.md#74-tip-1060-storage-credit-hook-from-t7)) | disabled |
| Explicit chapter charges | unchanged |

The write is a protocol-internal invocation, so no input charge (TIP-1100) applies. Warm and cold status are still tracked, so the slots and accounts it touches are warm afterwards. This table is identical to [precompiles/00-framework.md §9.1.1](precompiles/00-framework.md#911-t1t1a-metered-gas-table). On success its gas is added to `g` (so `execution_gas` shrinks by it). On out-of-gas the authorization is rolled back (including its events), the EIP-7702 authorization list is still applied (§4.11), and the transaction is **failed** without executing the batch: all `gas_limit` is consumed, the refund is 0, and it is settled as in §7.3. In that case a CREATE-first transaction with `nonce_key == 0` does not consume its protocol nonce (§4.8.1 defers that bump to the batch, which does not run).

### 4.11 EIP-7702 authorizations (`aa_authorization_list`)

Applied after key authorization, outside the batch checkpoint, in list order:

```python
for auth in tx.aa_authorization_list:
    if fork >= T0 and auth.signature is Keychain: continue        # silently ignored, no gas returned
    if auth.chain_id != 0 and auth.chain_id != chain.id: continue
    if auth.nonce == 2**64 - 1: continue
    authority = recover(auth)              # Tempo signature over the EIP-7702 message, 03-signatures.md
    if recovery failed: continue
    warm(authority)
    existed = account_exists(authority) or touched_in_this_tx(authority)
    if authority.code is non-empty and not a delegation designator: continue
    if auth.nonce != authority.nonce: continue
    authority.code = (b"" if auth.address == 0 else 0xef0100 || auth.address)
    authority.nonce += 1
    if fork < T1 and existed: refund_counter += AUTH_REFUND        # 12_500
```

`account_exists(a)` is true iff `a` is in the state as seen by this transaction so far (including changes made earlier in the transaction). `touched_in_this_tx(a)` is true iff `a` has been touched (EIP-161) earlier in the current transaction and the touch has not been rolled back; touches from earlier transactions do not count, since the EIP-161 sweep at the end of each transaction clears them. This is the Osaka EIP-7702 `account_exists` check together with its treatment of touched accounts. The sender is touched in §4.8, so a self-authorization counts as existing. Skipped entries still paid their intrinsic gas.

### 4.12 Batch execution

```python
def execute_batch(tx, create_nonce, fork):
    cp = checkpoint()
    remaining = execution_gas
    if fork >= T3 and access_key is not None:                       # call-scope prevalidation
        with protocol_storage(gas_limit = remaining):                # normally metered
            for call in tx.calls:
                AccountKeychain.validate_call_scope_for_transaction(sender, access_key, call.to, call.input)
        on revert error e: rollback(cp); return Failed(stop=Revert, output=abi(e), gas_left=remaining - used, refund=0)
        on out of gas:     rollback(cp); return Failed(stop=OutOfGas, gas_left=0, refund=0)
        remaining -= used
    refund = 0
    for call in tx.calls:
        if call.to is an address: warm(call.to)
        if call.to is Create and sender.nonce == 2**64 - 1:
            r = Success(gas_left=remaining, refund=0)                # no execution, no nonce change
        elif call.to is Create:
            sender.nonce += 1
            r = create(caller=sender, address=create_address(sender, create_nonce),
                       initcode=call.input, value=0, gas=remaining)
        else:
            r = message_call(caller=sender, to=call.to, input=call.input, value=0, gas=remaining)
        if not r.success:                                            # revert or exceptional halt
            rollback(cp)
            if tx.nonce_key == 0 and tx.calls[0].to is Create:
                sender.nonce += 1                                     # CREATE nonce stays consumed
            return Failed(stop=r.stop, output=r.output, gas_left=r.gas_left, refund=0)
        refund += r.refund
        remaining = r.gas_left
    return Success(output=last r.output, gas_left=remaining, refund=refund)
```

Each call is a depth-0 frame that receives all remaining gas (no 63/64 retention), with `ORIGIN = CALLER = sender` and `GASPRICE = price`. The calls of a batch run inside one transaction, as the message calls of a single Osaka transaction would. Everything that Osaka scopes to a transaction is shared across the calls and is not reset between them: EIP-1153 transient storage, the EIP-2929 accessed-address and accessed-storage-key sets (including the warming of §4.7), the EIP-6780 set of contracts created in this transaction (a contract created by the first call and `SELFDESTRUCT`ed by a later call is deleted), the EIP-161 touched-account set and the self-destruct set. They end with the transaction. `create(...)` is a top-level creation message, the same as the creation message of an Osaka contract-creation transaction: it does not increment the caller's nonce. The only increment for a CREATE call is the explicit `sender.nonce += 1` before it. A call to an account carrying an EIP-7702 delegation runs the delegate's code (Osaka). An exceptional halt consumes all remaining gas (`gas_left = 0`); a revert returns its unused gas. `create_address(sender, n) = keccak256(rlp([sender, n]))[12:]` with `n = create_nonce`, the protocol nonce read in §4.8 before any bump: it equals `tx.nonce` for `nonce_key == 0`, and is the current protocol nonce for 2D and expiring transactions, whose CREATE also increments the protocol nonce (rolled back if the batch fails). The batch is atomic: either all calls' state changes and logs persist, or none do. The call-scope matching rules (and its revert errors, such as `CallNotAllowed`) are in [precompiles/account-keychain.md](precompiles/account-keychain.md).

### 4.13 What survives a failed batch

| Effect | Persists when the batch fails |
|---|---|
| Protocol nonce (`nonce_key == 0`): CALL-first bump (§4.8.1) or CREATE-first re-bump (§4.12) | yes |
| 2D nonce increment and its `NonceIncremented` log | yes |
| Expiring-nonce replay record | yes |
| Protocol-nonce bump by a CREATE under a 2D or expiring key | no |
| Fee pre-collection, post-transaction settlement and the fee `Transfer` log | yes (settlement follows the batch) |
| Access-key fee deduction (§8) and its `AccessKeySpend` log | yes |
| Key authorization (key record, limits, scopes, witness) and its logs | yes |
| EIP-7702 delegations from `aa_authorization_list` | yes |
| State changes and logs of any call, including successful earlier calls | no |
| Refunds from successful earlier calls | no (refund counter is 0) |
| TIP-1060 storage-credit settlement (T7) | no (runs only on success) |

## 5. Fee payer and sponsorship

```python
def resolve_fee_payer(tx) -> Address:
    if tx.type != 0x76 or tx.fee_payer_signature is None:
        return sender
    payer = secp256k1_recover(tx.fee_payer_signature, fee_payer_signing_hash(tx, sender))  # 03-signatures.md
    if recovery failed: invalid()
    if fork >= T2 and payer == sender: invalid()      # self-sponsorship with a signature
    return payer
```

The fee payer chooses the fee token (it signs `fee_token`; the sender's payload omits it when a fee-payer signature is present, [03-signatures.md](03-signatures.md)), is the account whose fee-token balance is prechecked, debited before execution and refunded after it, and whose stored preference applies in §6. Before T2 a transaction MAY carry a fee-payer signature that recovers to the sender; it then behaves as self-paid. Only the transaction's fee is sponsored: the batch still executes as `sender`.

## 6. Fee token resolution and validation

### 6.1 Fee context

Run once per transaction (for `0x76` after warming, §4.7; for other types after the sender nonce bump, §3.2):

```python
def resolve_fee_context(tx):
    price = effective_gas_price(tx, header.base_fee_per_gas)            # §7.1
    max_fee = ceil_div(tx.gas_limit * max_fee_per_gas(tx), GAS_PRICE_SCALE)   # gas_price for types 0/1
    collected = ceil_div(tx.gas_limit * price, GAS_PRICE_SCALE)
    # transient context for the rest of the transaction:
    AccountKeychain.tx_origin = sender
    TIP20ChannelReserve.channel_open_context = keccak256(encode_for_signing(tx) + sender)
    token = resolve_fee_token(tx, fee_payer, max_fee)    # §6.2; may be invalid
    if token[0:12] != TIP20_PREFIX: invalid()            # FeeTokenNotTip20
    if max_fee != 0 and TIP20(token).currency != "USD": invalid()   # FeeTokenNotUsdCurrency
    if TIP20(token).balances[fee_payer] < max_fee: invalid()        # InsufficientFeeTokenBalance
    return FeeContext(payer=fee_payer, token=token, collected=collected)
```

The two transient values are cleared at the end of the transaction (EIP-1153 semantics); their use is specified in [precompiles/account-keychain.md](precompiles/account-keychain.md) and [precompiles/tip20.md](precompiles/tip20.md). The balance read is the TIP-20 balance storage of [precompiles/tip20.md](precompiles/tip20.md); a token address with the TIP-20 prefix that was never created has an empty currency and is rejected as non-USD.

### 6.2 Resolution order

The first rule that yields a token wins. Rules 1–3 never fall through: the token they yield is validated by §6.1 and a failure is invalid. Rules 4 and 5 apply only to a *valid fee token* (TIP-20 prefix and currency exactly "USD") and otherwise fall through to the next rule. `INFERENCE_SELECTORS(fork)` is defined right after the pseudocode.

```python
def resolve_fee_token(tx, fee_payer, max_fee):
    calls = tx.calls if tx.type == 0x76 else [(tx.to, tx.data)]   # tx.to is None for a CREATE
    # 1. Transaction field (0x76 only)
    if tx.type == 0x76 and tx.fee_token is not None:
        return tx.fee_token
    # 2. setUserToken shortcut (non-0x76 only; fee_payer == sender always holds there)
    if tx.type != 0x76 and calls[0].to == FEE_MANAGER \
       and abi_decodes(calls[0].input, "setUserToken(address)"):
        return decoded.token
    # 3. Stored account preference
    t = FeeManager.user_tokens[fee_payer]            # precompiles/fee-manager.md
    if t != 0:
        return t
    # 4. TIP-20 inference
    to = calls[0].to
    if to is not None and not (tx.type == 0x76 and fee_payer != sender):
        if all(c.to == to and len(c.input) >= 4 and c.input[0:4] in INFERENCE_SELECTORS(fork)
               for c in calls) and is_valid_fee_token(to):
            return to
    # 5. Stablecoin DEX inference
    if calls[0].to == STABLECOIN_DEX and (tx.type != 0x76 or len(calls) == 1):
        if abi_decodes(calls[0].input, "swapExactAmountIn(address,address,uint128,uint128)") \
           and is_valid_fee_token(decoded.tokenIn):
            return decoded.tokenIn
        if abi_decodes(calls[0].input, "swapExactAmountOut(address,address,uint128,uint128)") \
           and is_valid_fee_token(decoded.tokenIn):
            return decoded.tokenIn
    # 6. Fallback
    if fork < T13 or max_fee == 0:
        return PATH_USD
    for t in [PATH_USD, OUSD]:                       # TIP-1115
        if TIP20(t).balances[fee_payer] >= max_fee:
            return t
    invalid()                                        # InsufficientFeeTokenBalance (reports the richest candidate)
```

`INFERENCE_SELECTORS(fork)` are the selectors of `transfer(address,uint256)` and `transferWithMemo(address,uint256,bytes32)`, plus, before T7, `distributeReward(uint256)`. Only the 4-byte prefix is checked for inference. `abi_decodes(input, sig)` means non-validating decoding of a call with the static argument types of `sig` ([Solidity ABI specification](https://docs.soliditylang.org/en/latest/abi-spec.html)): the input MUST begin with the function's 4-byte selector and MUST contain at least the argument words (1 for `setUserToken`, 4 for the swaps); bytes after them are ignored, an `address` is taken from the low 20 bytes of its word and a `uint128` from the low 16 bytes, and the discarded high-order bytes need not be zero.

Only an insufficient balance advances the T13 fallback; once a fallback token is chosen, §6.1 and §7.2 apply to it and a failure there does not try the next token.

## 7. Fee charging and settlement

### 7.1 Units and prices

Gas prices and `base_fee_per_gas` are in attodollars (`10**-18` USD) per gas; TIP-20 amounts are in microdollar base units (6 decimals). `ceil_div(a, b) = (a + b - 1) // b` on unbounded integers (the product saturates at `2**256 - 1`, which no valid transaction reaches).

```python
def effective_gas_price(tx, base_fee) -> int:
    if tx.type in (0, 1): return tx.gas_price
    return min(tx.max_fee_per_gas, base_fee + tx.max_priority_fee_per_gas)   # types 2, 4, 0x76

def fee_amount(gas, price) -> int:
    return ceil_div(gas * price, GAS_PRICE_SCALE)
```

The whole effective price, base fee included, is paid to the block's fee recipient through the FeeManager; nothing is burned.

### 7.2 Pre-collection

```python
def collect_fee_pre_tx(fee, keychain):
    if fee.collected == 0: return
    cp = checkpoint()
    try:
        FeeManager.collect_fee_pre_tx(fee.payer, fee.token, fee.collected, header.beneficiary)
    except error:
        rollback(cp); invalid()
    if fork >= T7:
        mark_non_creditable(fee_token_balance_slot(fee.token, fee.payer),
                            keychain_limit_slot(fee.payer, keychain.fee_key, fee.token)
                                if tx.type == 0x76 and fee.payer == sender and keychain.fee_key else None)
```

`FeeManager.collect_fee_pre_tx` is specified in [precompiles/fee-manager.md](precompiles/fee-manager.md). From the handler's point of view it: resolves the validator token of `header.beneficiary` (pathUSD if unset); checks the TIP-403 policy of the fee token (before T8 a transfer authorization from `fee.payer` to `FEE_MANAGER`; from T8, TIP-1042, `fee.payer` authorized as sender only); requires the fee token not to be paused; applies the access-key spending limit for the fee (§8); moves `collected` from `fee.payer` to `FEE_MANAGER` without a `Transfer` log; and requires a fee AMM route with enough liquidity for `collected` (reserving it on the Direct route from T1C and on two-hop routes from T5). Every failure (paused token, insufficient balance, policy, spending limit, insufficient liquidity) makes the transaction **invalid**.

`fee_key` is `access_key` when the existing key enforces limits (§4.9 step 3) or when a same-transaction key has inline limits and is sender-paid with a non-zero fee (§4.9 step 2). From T7, clearing a non-creditable slot during the transaction mints no TIP-1060 storage credit ([precompiles/account-keychain.md](precompiles/account-keychain.md), storage credits); the two slots are the fee payer's fee-token balance and the access key's `remaining` limit for the fee token.

### 7.3 Gas finalization

After execution (or after the T1/T1A key-authorization out-of-gas, §4.10.2), for every transaction type:

```python
def finalize_gas(tx, result, floor) -> int:
    refund_counter = result.refund                       # 0 if the execution failed
    if tx.type == 0x76:
        refund_counter += aa_auth_refund                 # §4.11, non-zero only before T1
    if fork >= T7 and result.success:
        refund_counter += settle_storage_credits() * STORAGE_CREDIT_VALUE
    if refund_counter < 0:
        refund_counter = 2**63 - 1                       # net-negative counter refunds the full cap
    spent = tx.gas_limit - result.gas_left
    refund = min(refund_counter, spent // MAX_REFUND_QUOTIENT) if refund_counter > 0 else 0
    return max(spent - refund, floor)                    # gas_used
```

`settle_storage_credits()` (TIP-1060, from T7, successful transactions only): for each owner with pending credit refunds `p` recorded during the transaction and a stored credit balance `b`, consume `min(p, b)` credits from the balance and count them; it returns the total consumed. Its storage is in [precompiles/account-keychain.md](precompiles/account-keychain.md). With `MAX_REFUND_QUOTIENT = 1` from T7, refunds are uncapped down to the EIP-7623 floor. For the T1/T1A key-authorization out-of-gas case, `gas_left = 0` and `refund_counter = 0`, so `gas_used = gas_limit`.

`gas_used` is the transaction's gas used for the receipt and for block accounting ([05-block-execution.md](05-block-execution.md)).

### 7.4 Post-transaction settlement

```python
def settle_fee(fee, gas_used, price):
    actual = fee_amount(gas_used, price)
    collected = fee_amount(tx.gas_limit, price)        # == fee.collected
    refund_amount = collected - actual                 # each term rounded up separately
    if actual == 0 and refund_amount == 0:
        return                                         # no post-transaction call, no Transfer log
    try:
        FeeManager.collect_fee_post_tx(fee.payer, actual, refund_amount, fee.token, header.beneficiary)
    except error:
        invalid()
```

`FeeManager.collect_fee_post_tx` ([precompiles/fee-manager.md](precompiles/fee-manager.md), [precompiles/tip20.md](precompiles/tip20.md)) first emits, at the fee token, `Transfer(from=fee.payer, to=FEE_MANAGER, amount=actual)`; then, if `refund_amount > 0`, from T1C restores the access-key limit by `refund_amount` (§8) and moves `refund_amount` from `FEE_MANAGER` back to `fee.payer` (allowed even if the token is paused; no log); then converts `actual` to the validator token through the fee AMM at 0.9970 per hop (rounded down) and adds it to the beneficiary's collected fees. These steps run regardless of the batch outcome. A failure here makes the transaction invalid.

> **Resolved conflict C-TXF-07**: the fee specification gives the refund as `(gas_limit - gas_used) * gas_price`; the code refunds `ceil(gas_limit*price/10^12) - ceil(gas_used*price/10^12)`, which can differ by one base unit. Decided: this spec follows the implementation, and the docs are fixed in [tempoxyz/docs#1098](https://github.com/tempoxyz/docs/pull/1098). See [conflicts](conflicts.md#c-txf-07).

## 8. Access-key spending limits on fees

Spending limits bind only `0x76` transactions signed with a Keychain signature, and only the fee paid by the sender itself (the AccountKeychain applies a limit only when the paying account equals `tx.origin = sender`). A sponsored fee never counts against the sender's key.

| Case | When the fee is charged to the key | Refund to the key |
|---|---|---|
| Existing key with enforced limits, sender-paid | at pre-collection, `collected` is deducted from the key's remaining limit for the fee token (insufficient: invalid); from T3 an `AccessKeySpend` log is emitted | from T1C, `refund_amount` is added back at settlement if the key is still active (T3+: clamped to the configured maximum when one is stored); before T1C nothing is restored |
| Same-transaction key (§4.9 step 2), sender-paid | inline precheck before pre-collection (invalid if over), then deducted right after the key is written (§4.10); `AccessKeySpend` from T3 | as above |
| Unlimited key (`limits` absent) or root signature | never | — |

During execution the TIP-20 precompile enforces the transaction key's limits on the sender's own transfers and approvals; exceeding a limit there reverts that call (a failed transaction, not an invalid one). Period rollover, the T7 zero-remaining sentinel and the exact storage are in [precompiles/account-keychain.md](precompiles/account-keychain.md).

## 9. Receipts

A transaction's receipt has exactly four consensus fields ([02-encoding.md](02-encoding.md) gives the encoding): `tx_type`, `status` (1 successful, 0 failed), `cumulative_gas_used` (the sum of `gas_used` of this and all earlier transactions of the block, as accounted in [05-block-execution.md](05-block-execution.md)) and `logs`; the bloom is derived from the logs. Receipts carry no fee token, fee amount or fee payer.

`logs` are all logs the transaction emitted that were not rolled back, in emission order. Because protocol actions run outside the batch checkpoint, a failed (status 0) receipt MAY contain logs. For a `0x76` transaction the order is:

| # | Log (emitter) | When |
|---|---|---|
| 1 | `NonceIncremented(address indexed account, uint256 indexed nonceKey, uint64 newNonce)` (`NONCE_MANAGER`) | 2D nonce key (§4.8.2) |
| 2 | `AccessKeySpend(address indexed account, address indexed publicKey, address indexed token, uint256 amount, uint256 remainingLimit)` (`ACCOUNT_KEYCHAIN`) | from T3; existing key with enforced limits, sender-paid fee (§8) |
| 3 | `KeyAuthorizationWitness(address indexed account, bytes32 indexed witness)`, then `KeyAuthorized(address indexed account, address indexed publicKey, uint8 signatureType, uint64 expiry)`, then for an admin key `AdminKeyAuthorized(address indexed account, address indexed publicKey)` (`ACCOUNT_KEYCHAIN`) | `key_authorization` present; witness from T5, admin from T6; absent after a T1/T1A out-of-gas rollback |
| 4 | `AccessKeySpend(...)` (`ACCOUNT_KEYCHAIN`) | from T3; same-transaction key with enforced limits, sender-paid non-zero fee (§4.10) |
| 5 | logs of the calls | successful batch only |
| 6 | `Transfer(address indexed from = fee payer, address indexed to = FEE_MANAGER, uint256 amount = actual)` (the fee token) | unless `actual == 0` and `refund_amount == 0` (§7.4) |

For types 0, 1, 2 and 4 the logs are the execution's logs (successful execution only) followed by the fee `Transfer` log (row 6); fee pre-collection emits no log for these transaction types. For every transaction type, the refund, the fee AMM conversion, expiring-nonce bookkeeping, EIP-7702 delegation and storage-credit settlement emit no logs.

## 10. Consensus rules versus transaction-pool policy

The following limits are transaction-pool policy only and are **not** block-validity rules; a block containing a transaction that violates them is valid if it satisfies this chapter: at most 32 calls per `0x76` transaction; at most 128 KiB of `input` per call; at most 16 `aa_authorization_list` entries; at most 256 access-list addresses, 256 storage keys per address and 2,048 storage keys in total; at most 256 token limits per key authorization; at most 64 call scopes per key, 64 selector rules per scope and 64 recipients per selector; `valid_after` at most 120 s in the future; `valid_before` at least 3 s in the future; the pool's own fee-AMM liquidity cache and the option of skipping the liquidity and `valid_after` checks during pool admission. Block-level validity always applies the full checks of §4.5 and §7.2.

## 11. Fork history of the rules in this chapter

| Fork | Changes |
|---|---|
| Before T0 (Moderato only) | 2D nonce gas added after the intrinsic check (with the `2**64 - 1` execution-gas fallback); Keychain-signed `aa_authorization_list` entries are processed |
| T0 (mainnet genesis) | 2D nonce gas included in the intrinsic check; Keychain-signed `aa_authorization_list` entries are ignored |
| T1 | TIP-1000 costs (§1.5; +250,000 for `nonce == 0` and for each zero-nonce authorization; 12,500 per authorization, no authorization refund); expiring nonces (30 s, 300,000, replay key = tx hash, `nonce == 0`); Keychain signature type checked against the stored key type; key authorization additionally metered (§4.10.2) |
| T1A | `TX_GAS_LIMIT_CAP` 16,777,216 → 30,000,000 (same timestamp as T1 on mainnet) |
| T1B | exact key-authorization intrinsic gas, unmetered write; expiring replay key `keccak256(encode_for_signing \|\| sender)` |
| T1C | Keychain V2 signatures required (V1 rejected, V2 rejected before); key-authorization `chain_id` 0 wildcard removed; Direct-route fee liquidity reservation; fee refund restores the access-key limit |
| T2 | self-sponsored fee-payer signature rejected; 2D nonce key gas +200 |
| T3 | periodic limits (2 slots per limit) and call scopes in key authorizations; same-transaction key type must match the Keychain signature; access-key transactions cannot start with CREATE; call-scope prevalidation; `AccessKeySpend` logs |
| T4 | call-scope slot count changed and rounded scope overhead added (§4.6.1) |
| T5 | key-authorization witness (+2,100 + 1,500 gas); two-hop fee routes |
| T6 | admin access keys and admin-signed authorizations (`is_admin`, `account`; +1,500 gas for admin) |
| T7 | TIP-1060: `SSTORE_SET_COST` 5,000 with key-authorization writes priced at 5,000 + 245,000; `MAX_REFUND_QUOTIENT` 1; storage-credit settlement; non-creditable fee slots; `distributeReward` no longer infers the fee token |
| T8 | fee pre-collection checks only the fee payer's sender authorization (TIP-1042) |
| T11 | expiring window 300 s, capacity 3,000,000 (TIP-1093) |
| T12 | expiring-nonce `nonce` may be any uint64 (TIP-1106) |
| T13 | ordered fallback fee tokens [pathUSD, OUSD] (TIP-1115) |
