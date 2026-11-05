# 05 — Block execution

Status: normative. Applies to Tempo mainnet (chain id 4217) from genesis through T13.

This chapter specifies how a Tempo block is validated and executed by the execution layer: the EVM rule set Tempo inherits and the Tempo modifications to it, the header checks the execution layer performs, the order of state transitions inside a block (pre-block changes, the transaction loop with its block-section and payment-lane accounting, post-block changes) and the checks applied to the execution result.

It does **not** specify per-transaction validation and processing (intrinsic gas, nonces, key authorizations, fee-token resolution and fee charging, protocol-emitted logs). Those are in [06-transactions-and-fees.md](06-transactions-and-fees.md); this chapter calls them as a black box `execute_tx`. Wire formats are in [02-encoding.md](02-encoding.md); the state model and genesis in [04-state-and-genesis.md](04-state-and-genesis.md); precompile behaviour in the `precompiles/` chapters.

## 0. Conventions

- The key words MUST, MUST NOT, SHOULD, MAY are to be interpreted as in RFC 2119.
- **Fork predicate.** "Fork F is active" for a block means `header.timestamp >= activation_time(F)`, as defined in [01-chain-and-forks.md](01-chain-and-forks.md). `header.timestamp` is the header's seconds field (not the millisecond timestamp). Forks are totally ordered (Genesis < T0 < T1 < T1A < T1B < T1C < T2 < … < T13) and every fork's rules include all earlier forks' rules unless stated otherwise. "From F:" means "for every block in which F is active"; "Before F:" means "for every block in which F is not active".
- On mainnet T0 is active from genesis (timestamp 0), so the pre-T0 ("Genesis") rules never apply to a mainnet block and are not specified here. Moderato (chain id 42431) has a pre-T0 era that is out of scope.
- "Ethereum rules" means the rules of the Ethereum execution layer as of the Osaka fork, as specified in `ethereum/execution-specs` (`osaka`), and the EIPs named.
- "Invalid block": a block for which any MUST in this chapter fails. An invalid block MUST be rejected in its entirety; none of its state changes are kept.
- Integers are unsigned unless stated. `a // b` is floor division. `saturating_sub(a, b) = max(a - b, 0)`.
- Addresses are written in hex; comparisons are on the 20 raw bytes.

### 0.1 Constants used in this chapter

| Name | Value |
|---|---|
| `SYSTEM_ADDRESS` (Ethereum system-call sender) | `0xfffffffffffffffffffffffffffffffffffffffe` |
| `ETH_SYSTEM_CALL_GAS_LIMIT` | `30_000_000` |
| `TEMPO_SYSTEM_CALL_GAS_LIMIT` | `250_000_000` |
| `HISTORY_STORAGE_ADDRESS` (EIP-2935) | `0x0000F90827F1C53a10cb7A02335B175320002935` |
| `BEACON_ROOTS_ADDRESS` (EIP-4788) | `0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02` |
| `WITHDRAWAL_REQUEST_ADDRESS` (EIP-7002) | `0x00000961Ef480Eb55e80D19ad83579A64c007002` |
| `CONSOLIDATION_REQUEST_ADDRESS` (EIP-7251) | `0x0000BBdDc7CE488642fb579F8B00f3a590007251` |
| `MAINNET_DEPOSIT_CONTRACT_ADDRESS` (mainnet genesis `config.depositContractAddress`) | `0x0000000000000000000000000000000000000000` |
| `EMPTY_REQUESTS_HASH` (EIP-7685, `sha256(b"")`) | `0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `CURRENT_COMMITTEE_ADDRESS` | `0xC077E00000000000000000000000000000000000` |
| `MARKER_CODE` | the single byte `0xEF` (code hash `0x309b8896ee4c1ff7ec1966155373dee42663b6b40c3fedc70ba501684848d2a3`) |
| `TEMPO_MAXIMUM_EXTRA_DATA_SIZE` | `10_240` bytes |
| `TEMPO_SUBBLOCK_NONCE_KEY_PREFIX` | `0x5B` |
| `TEMPO_T0_BASE_FEE` | `10_000_000_000` |
| `TEMPO_T1_BASE_FEE` | `20_000_000_000` |
| `TEMPO_T7_BASE_FEE_CAP` | `12_000_000_000` |
| `TEMPO_T7_BASE_FEE_FLOOR` | `600_000_000` (`CAP // 20`) |
| `TEMPO_T7_BASE_FEE_GAS_TARGET` | `10_000_000` |
| `TEMPO_T7_BASE_FEE_MAX_CHANGE_DENOMINATOR` | `8` |
| `TEMPO_T1_GENERAL_GAS_LIMIT` | `30_000_000` |
| `MAX_TX_GAS_LIMIT_OSAKA` (EIP-7825) | `16_777_216` (2^24) |
| `TEMPO_T1_TX_GAS_LIMIT_CAP` | `30_000_000` |
| `GAS_LIMIT_BOUND_DIVISOR` | `1024` |
| `MINIMUM_GAS_LIMIT` | `5000` |
| `MAXIMUM_GAS_LIMIT_BLOCK` | `2^63 - 1` |
| `MAX_RLP_BLOCK_SIZE` (EIP-7934) | `8_388_608` bytes |
| `STORAGE_CREDIT_VALUE` (TIP-1060) | `245_000` |
| `EPOCH_LENGTH` (mainnet genesis `config.epochLength`) | `21_600` blocks |

Reference implementation: crates/hardfork/src/constants.rs, crates/evm/src/evm.rs, crates/evm/src/consensus/mod.rs, crates/chainspec/src/genesis/presto.json.

---

## 1. EVM base and Tempo modifications

### 1.1 Ethereum rule set

Every Tempo fork from T0 through T13 executes with the Ethereum **Osaka** rule set (`SpecId::OSAKA`). The mainnet genesis activates every Ethereum fork up to and including Osaka at genesis (`homestead` … `londonBlock = 0`, `mergeNetsplitBlock = 0`, `terminalTotalDifficulty = 0`, `shanghaiTime = cancunTime = pragueTime = osakaTime = 0`; no DAO fork). Therefore every mainnet block is a post-merge, Osaka block, and all EIPs included in the Ethereum hard forks through Osaka apply, except where this chapter modifies them. Amsterdam (and with it EIP-7928 block access lists, EIP-8037 and EIP-8282) is not scheduled and MUST NOT be applied.

In particular the following inherited rules apply unchanged unless a later section says otherwise: EIP-150, EIP-155, EIP-158/161 (state clearing), EIP-1153, EIP-1559 (effective gas price and the `maxFeePerGas >= baseFee` rule; see §1.4 for burn), EIP-2028, EIP-2200/EIP-2929/EIP-3529 SSTORE metering as parameterised in §1.7, EIP-2930, EIP-3198, EIP-3541, EIP-3651 (warm `COINBASE`), EIP-3855, EIP-3860, EIP-4399 (`PREVRANDAO`), EIP-4844 opcodes (`BLOBHASH`, `BLOBBASEFEE`), EIP-5656, EIP-6780, EIP-7516, EIP-7623 (calldata floor), EIP-7702, EIP-7825 (with Tempo's cap, §1.8), EIP-7934, EIP-7939 (`CLZ`), EIP-170 (24,576-byte code size limit).

Reference implementation: crates/hardfork/src/lib.rs (`From<TempoHardfork> for SpecId`), crates/evm/src/handler/config.rs (`tempo_execution_config`).

### 1.2 Transaction types

A block MAY contain transactions of types `0x00` (legacy), `0x01` (EIP-2930), `0x02` (EIP-1559), `0x04` (EIP-7702) and `0x76` (Tempo transaction). Type `0x03` (EIP-4844 blob transactions) does not exist on Tempo: such an envelope is not decodable (see [02-encoding.md](02-encoding.md)) and a block containing one is invalid. Consequently every transaction's blob gas is zero and `BLOBHASH` always returns zero.

A legacy transaction whose signature is `(r = 0, s = 0, y_parity = false)` is a **system transaction** (§5.5); it is processed by the system-transaction path and never by the ordinary legacy path.

Reference implementation: crates/primitives/src/transaction/envelope.rs, crates/evm/src/handler/config.rs (`tempo_tx_registry`).

### 1.3 Precompiles

**Ethereum precompiles.**

- Before T1C: exactly the Prague precompile set: `0x01` ECRECOVER, `0x02` SHA256, `0x03` RIPEMD160, `0x04` IDENTITY, `0x05` MODEXP (EIP-198 with EIP-2565 pricing, without the Osaka changes), `0x06`–`0x08` BN254 add/mul/pairing (EIP-196/197 with EIP-1108 pricing), `0x09` BLAKE2F, `0x0a` KZG point evaluation (EIP-4844), `0x0b`–`0x11` BLS12-381 (EIP-2537). Address `0x0100` is **not** a precompile before T1C (a call to it is a call to an ordinary account).
- From T1C: exactly the Osaka precompile set: the Prague set with MODEXP changed by EIP-7823 (input-length bounds) and EIP-7883 (repricing), plus `0x0100` P256VERIFY (EIP-7951).

**Tempo precompiles.** In addition, the Tempo precompiles (TIP-20 tokens, fee manager, DEX, keychain, nonce manager, validator config, …) are dispatched by address as specified in [precompiles/00-framework.md](precompiles/00-framework.md). For EIP-2929 purposes only the Ethereum precompile addresses of the active set are added to the transaction's initial warm address set; Tempo precompile addresses are not pre-warmed.

Reference implementation: crates/precompiles/src/lib.rs (`TempoPrecompiles::new`, `warm_addresses`).

### 1.4 No native token

Tempo has no native value-bearing token. The following rules hold at every fork:

1. Every account's native balance is zero in the mainnet genesis state, and no rule in this specification ever credits a native balance: there are no block or ommer rewards, no withdrawals (§4.1), no priority-fee or base-fee payment to the beneficiary in native units, and transactions cannot carry value (rule 2). Hence every account's native balance is zero in every state, and `BALANCE` and `SELFBALANCE` always return 0.
2. The top-level `value` of every legacy, EIP-2930, EIP-1559 and EIP-7702 transaction MUST be 0; otherwise the transaction is invalid (`ValueTransferNotAllowed`). For type `0x76` every call's `value` MUST be 0 (see [06-transactions-and-fees.md](06-transactions-and-fees.md)). The system transaction's `value` MUST be 0 (§5.5).
3. The Ethereum native-balance sufficiency check for the up-front gas cost (`balance >= gas_limit * max_fee_per_gas + value`) MUST NOT be performed, and the sender's native balance MUST NOT be topped up or debited for gas. (Because balances are always zero, a saturating debit would be a no-op.)
4. Inside the EVM, `CALL`/`CALLCODE`/`CREATE`/`CREATE2` with non-zero value follow Ethereum rules unchanged: gas (including the value-transfer and new-account surcharges of §1.7) is charged, and the value transfer then fails for insufficient balance (the sub-call/creation is not executed and the opcode pushes 0). `SELFDESTRUCT` transfers a zero balance.
5. Fees are paid in TIP-20 tokens by the fee-payment procedure of [06-transactions-and-fees.md](06-transactions-and-fees.md) and [precompiles/fee-manager.md](precompiles/fee-manager.md). Neither the base fee nor the priority fee is burned; the Ethereum native refund of unused gas and the native beneficiary reward MUST NOT be applied.

Reference implementation: crates/evm/src/handler/config.rs (`tempo_execution_config` removes `BALANCE_CHECK` and `BALANCE_TOP_UP`; `validate_no_native_value`; `settle_transaction`), crates/chainspec/src/genesis/presto.json.

### 1.5 Block environment

The EVM block environment of a block is derived from its header ([02-encoding.md](02-encoding.md) §header):

| EVM input | Value |
|---|---|
| `NUMBER` | `header.number` |
| `COINBASE` (beneficiary) | `header.beneficiary` |
| `TIMESTAMP` | `header.timestamp` (seconds) |
| millisecond timestamp (used by `0x4F`, §1.6.1) | `header.timestamp * 1000 + header.timestamp_millis_part` |
| `GASLIMIT` | `header.gas_limit` |
| `BASEFEE` | `header.base_fee_per_gas` (attodollars per gas) |
| `PREVRANDAO` | `header.mix_hash` interpreted as a big-endian 256-bit integer |
| `BLOBBASEFEE` | `fake_exponential(1, header.excess_blob_gas, update_fraction)` per EIP-4844 with the Osaka blob parameters; since `excess_blob_gas` is always 0 (§2.2) this is 1 |
| `CHAINID` | 4217 |
| epoch length (used by §6.2) | `EPOCH_LENGTH` from the chain configuration (mainnet 21,600) |

The Tempo-specific header fields `general_gas_limit` and `shared_gas_limit` are inputs to block-section accounting (§5.4).

Reference implementation: crates/evm/src/lib.rs (`evm_env`), crates/primitives/src/block.rs (`TempoBlockExt::timestamp_millis`).

### 1.6 Opcode overrides

Tempo starts from the Osaka opcode table and overrides exactly three opcodes.

#### 1.6.1 `0x4F` — millisecond timestamp (before T1C only)

- Before T1C: `0x4F` is defined. It takes no stack inputs, costs 2 gas, and pushes `header.timestamp * 1000 + header.timestamp_millis_part` as a 256-bit word. Ordinary stack-overflow rules apply.
- From T1C: `0x4F` is undefined; executing it is an exceptional halt (invalid opcode), exactly like any other undefined opcode in Osaka.

#### 1.6.2 `SSTORE` (`0x55`)

`SSTORE` keeps the Ethereum (EIP-2200 + EIP-2929 + EIP-3529) semantics, parameterised by the per-fork gas schedule in §1.7, with one addition from T7. Let `O`, `P`, `N` be the original (start of transaction), present and new values of the slot, as in EIP-2200. Execution of `SSTORE(key, N)` in a frame whose storage owner is `A`:

1. If the frame is static: exceptional halt.
2. If `gas_left <= 2300` (`CallStipend`): exceptional halt (EIP-2200 sentry).
3. Charge `SstoreStatic` (= `WarmStorageReadCost` = 100).
4. Perform the write and determine whether the slot was cold (EIP-2929; the slot becomes warm).
5. From T7: run the TIP-1060 storage-credit hook for the transition `(A, key, O, P, N)` as specified in [precompiles/account-keychain.md](precompiles/account-keychain.md) §Storage credits. The hook acts only when the slot crosses the zero boundary (`P == 0 != N` or `P != 0 == N`) and `A != STORAGE_CREDITS_ADDRESS` (`0x1060000000000000000000000000000000000000`); it may charge gas (including the 245,000-gas creditable portion of a creation), mint or consume storage credits, and update the storage-credit transient state.
6. Charge the dynamic gas:
   ```python
   def sstore_dynamic_gas(O, P, N, is_cold, g):
       gas = g.ColdStorageCost if is_cold else 0          # 2,100
       if P != N and O == P:                               # not a no-op, slot clean
           gas += g.SstoreSetWithoutLoadCost if O == 0 else g.SstoreResetWithoutColdLoadCost
       return gas
   ```
7. Add the refund to the transaction's refund counter (may be negative):
   ```python
   def sstore_refund(O, P, N, g):
       if P == N: return 0
       if O == P and N == 0: return g.SstoreClearingSlotRefund
       r = 0
       if O != 0:
           if P == 0:   r -= g.SstoreClearingSlotRefund
           elif N == 0: r += g.SstoreClearingSlotRefund
       if N == O:
           r += g.SstoreSetRefund if O == 0 else g.SstoreResetRefund
       return r
   ```

If any charge exceeds the remaining gas the frame halts exceptionally (all its gas is consumed and its state changes, including hook effects, are reverted), so the relative order of steps 3–6 does not affect the result. With the §1.7 values the total gas of a clean creation (`O == P == 0 != N`) charged by steps 3 and 6 is:

| Fork | warm | cold |
|---|---|---|
| T0 | 20,000 | 22,100 |
| T1 – T6 | 250,100 | 252,200 |
| T7 + | 5,100 (+ hook, §1.6.2 step 5) | 7,200 (+ hook) |

> **Resolved conflict C-EXEC-05**: TIP-1000 states a cold zero-to-nonzero SSTORE costs 252,100 gas at T1; the code charges 252,200 (100 static + 250,000 + 2,100 cold). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-05).

> **Resolved conflict C-EXEC-06**: TIP-1060 states the T7 clean-creation residual is 5,000 gas in total (4,900 dynamic + 100 warm) and the 0→Y→0 restore refund is 4,900; the code charges 100 + 5,000 dynamic and refunds 5,000. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-06).

#### 1.6.3 `0xEF`

`0xEF` is undefined at every fork T0–T13: executing it is an exceptional halt (invalid opcode). (Accounts whose code is the one-byte `MARKER_CODE` installed by §4.5 are Tempo precompile addresses; calls to them are dispatched to the precompile and never execute the byte. EIP-3541 continues to forbid deploying new code that starts with `0xEF`.)

Reference implementation: crates/evm/src/instructions.rs (`millis_timestamp`, `sstore`, `configurable_account`), crates/evm/src/handler/config.rs (`tempo_opcode_config`).

### 1.7 Gas schedule per fork

Tempo uses the Osaka gas schedule with the overrides below. Parameters not listed (for example `ColdStorageCost` = 2,100, `ColdAccountAdditionalCost` = 2,500, `ColdStorageAdditionalCost` = 2,000, `WarmStorageReadCost` = `SstoreStatic` = 100, `SstoreResetWithoutColdLoadCost` = 2,800, `SstoreResetRefund` = 2,800, calldata token costs, EIP-7623 floor costs, EIP-3860 initcode word cost, memory, copy, log, Keccak, call-stipend and EIP-150 rules, precompile prices) keep their Osaka values at every fork.

| Parameter (meaning) | T0 (Osaka value) | T1 – T6 | T7 – T13 |
|---|---|---|---|
| `SstoreSetWithoutLoadCost` (clean-creation dynamic SSTORE cost, §1.6.2) | 19,900 | 250,000 | 5,000 |
| `SstoreSetRefund` (refund for restoring an originally-zero slot to zero) | 19,900 | 19,900 | 5,000 |
| `SstoreClearingSlotRefund` (EIP-3529 `SSTORE_CLEARS_SCHEDULE`) | 4,800 | 4,800 | 0 |
| `Create` (`CREATE`/`CREATE2` base cost) | 32,000 | 500,000 | 500,000 |
| `TxCreateCost` (intrinsic cost of a contract-creation transaction or call) | 32,000 | 500,000 | 500,000 |
| `NewAccountCost` (`CALL` with value to an empty account; also the T1 account-creation intrinsic charge of [06](06-transactions-and-fees.md)) | 25,000 | 250,000 | 250,000 |
| `NewAccountCostForSelfdestruct` | 25,000 | 250,000 | 250,000 |
| `CodeDepositCost` (per byte of deployed code) | 200 | 1,000 | 1,000 |
| `TxEip7702PerEmptyAccountCost` (EIP-7702 per-authorization intrinsic cost) | 25,000 | 12,500 | 12,500 |
| `TxEip7702AuthRefund` (EIP-7702 refund for an authorization whose authority already exists) | 12,500 | 0 | 0 |
| `MaxRefundQuotient` (EIP-3529 refund cap divisor) | 5 | 5 | 1 |

The T1 values implement TIP-1000; the T7 values implement TIP-1060. How the transaction-level intrinsic gas uses `TxCreateCost`, `NewAccountCost` and `TxEip7702PerEmptyAccountCost` is specified in [06-transactions-and-fees.md](06-transactions-and-fees.md). The EIP-8037 state-gas parameters are not used (§1.10).

> **Resolved conflict C-EXEC-04**: TIP-1000 says the nonzero→zero SSTORE clearing refund stays 15,000 gas; the code uses 4,800 (EIP-3529) at T0–T6 and 0 from T7. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-04).

Reference implementation: crates/hardfork/src/gas_params.rs (`configure_version`, `apply_t1`, `apply_t7`, `test_gas_params_per_hardfork`).

### 1.8 Transaction gas limit cap (EIP-7825)

The per-transaction gas limit cap of EIP-7825 is:

- Before T1A: `MAX_TX_GAS_LIMIT_OSAKA` = 16,777,216.
- From T1A: `TEMPO_T1_TX_GAS_LIMIT_CAP` = 30,000,000.

A non-system transaction whose `gas_limit` exceeds the cap is invalid. The cap applies to every non-system transaction type, including `0x76`. It does not apply to system transactions or system calls. (On mainnet T1A activates together with T1, so the 16,777,216 cap applies to T0 blocks only.)

> **Resolved conflict C-EXEC-03**: TIP-1010 describes the previous transaction gas cap as 16,000,000; the code uses EIP-7825's 16,777,216 before T1A. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-03).

Reference implementation: crates/hardfork/src/lib.rs (`tx_gas_limit_cap`), crates/evm/src/lib.rs (`resolved_env`).

### 1.9 Refund finalization

At the end of every non-system transaction, after execution of the top-level frame(s) and before fees are settled ([06-transactions-and-fees.md](06-transactions-and-fees.md)), the gas used is finalized as follows. Let `gas_limit` be the transaction gas limit, `gas_left` the gas remaining after execution, `refund_counter` the signed refund counter accumulated by successful frames (as in Ethereum, refunds recorded in a reverted or halted frame are discarded), and `floor_gas` the EIP-7623 calldata floor of the transaction (computed as in [06](06-transactions-and-fees.md); 0 if not applicable).

```python
def finalize_gas(tx, fork, success):
    # 1. TIP-1060 end-of-transaction settlement (T7+, successful transactions only).
    if fork >= T7 and success:
        settled = 0
        for (account_slot, transient) in storage_credit_transient_entries():   # transient storage of
            if transient.pending_refunds == 0:                                   # STORAGE_CREDITS_ADDRESS
                continue
            balance = sload(STORAGE_CREDITS_ADDRESS, account_slot)   # u64 credit balance
            credits = min(transient.pending_refunds, balance)
            if credits == 0:
                continue
            sstore(STORAGE_CREDITS_ADDRESS, account_slot, balance - credits)  # no gas, no TIP-1060 hook
            settled += credits
        refund_counter += settled * STORAGE_CREDIT_VALUE                       # 245,000 per credit
    # 2. A net-negative refund counter refunds the full cap.
    if refund_counter < 0:
        refund_counter = 2**63 - 1
    # 3. EIP-3529 cap with the per-fork quotient (5 before T7, 1 from T7).
    gas_spent = gas_limit - gas_left
    refund = min(refund_counter, gas_spent // MaxRefundQuotient) if refund_counter > 0 else 0
    # 4. EIP-7623 floor.
    tx_gas_used = max(gas_spent - refund, floor_gas)
    return tx_gas_used
```

The layout of the storage-credit transient entries and the credit-balance slot are specified in [precompiles/account-keychain.md](precompiles/account-keychain.md) §Storage credits. The settlement writes are protocol writes: they are part of the transaction's state changes but are not metered and do not run the TIP-1060 hook.

Consequences: before T7 at most `gas_spent // 5` is refunded; from T7 the refund may reach `gas_spent`, so `tx_gas_used` can fall to `floor_gas`. A negative final refund counter (step 2) refunds the maximum allowed by step 3.

`tx_gas_used` is the transaction's gas used for every purpose in this chapter: the receipt's cumulative gas, the header `gas_used`, the per-transaction block-gas check and block-section accounting (§5.4).

Reference implementation: crates/evm/src/handler/config.rs (`settle_transaction`, `settle_storage_credit_refunds`).

### 1.10 TIP-1016 / EIP-8037 is disabled

The regular/state gas split of TIP-1016 (EIP-8037 "state gas" and reservoir) is not active at any fork T0–T13: no transaction or system call has a state-gas dimension, and the block's gas used is the sum of `tx_gas_used` (§1.9). Implementations MUST NOT apply TIP-1016.

Reference implementation: crates/evm/src/handler/config.rs (`tempo_execution_config` passes `amsterdam_eip8037_enabled = false`).

---

## 2. Header and body checks performed with execution

These checks are part of block validity. A block failing any of them is invalid. Header-encoding rules (field presence and order, `consensus_context`) are in [02-encoding.md](02-encoding.md); consensus-layer checks (signatures, proposer, DKG data in `extra_data`) are in [07-consensus.md](07-consensus.md). The relative order in which a client evaluates the checks of §2 is not significant for validity.

### 2.1 Standalone header checks

For every non-genesis header `h`:

1. `h.timestamp_millis_part < 1000`.
2. Post-merge fields (Paris is active at block 0): `h.difficulty == 0`, `h.nonce == 0x0000000000000000`, `h.ommers_hash == EMPTY_OMMER_ROOT_HASH` (`0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347`).
3. `len(h.extra_data) <= TEMPO_MAXIMUM_EXTRA_DATA_SIZE` (10,240 bytes; this replaces Ethereum's 32-byte limit).
4. `h.gas_used <= h.gas_limit` and `h.gas_limit <= MAXIMUM_GAS_LIMIT_BLOCK`.
5. `h.base_fee_per_gas` is present.
6. `h.withdrawals_root` is present (Shanghai).
7. `h.blob_gas_used`, `h.excess_blob_gas` and `h.parent_beacon_block_root` are present (Cancun); `h.blob_gas_used` is a multiple of 131,072 and does not exceed the Osaka maximum blob gas per block.
8. `h.requests_hash` is present (Prague).
9. `h.block_access_list_hash` and `h.slot_number` are absent (Amsterdam is not active).
10. `h.shared_gas_limit == shared_gas_limit(fork, h.gas_limit)` and `h.general_gas_limit == general_gas_limit(fork, h.gas_limit, h.shared_gas_limit)` (§2.3).

There is no check of the header timestamp against wall-clock time in the execution layer.

### 2.2 Checks against the parent header

For every non-genesis header `h` with parent `p`:

1. `h.parent_hash == hash(p)` and `h.number == p.number + 1`.
2. Millisecond timestamps strictly increase: `h.timestamp * 1000 + h.timestamp_millis_part > p.timestamp * 1000 + p.timestamp_millis_part`. (Ethereum's seconds-only rule `h.timestamp > p.timestamp` is **not** applied; two consecutive blocks MAY have the same `timestamp` seconds value.)
3. Gas-limit bounds (Ethereum rule, London is active from genesis so no elasticity adjustment applies):
   ```python
   if h.gas_limit > p.gas_limit:
       assert h.gas_limit - p.gas_limit < p.gas_limit // GAS_LIMIT_BOUND_DIVISOR
   else:
       assert p.gas_limit - h.gas_limit < p.gas_limit // GAS_LIMIT_BOUND_DIVISOR
   assert h.gas_limit >= MINIMUM_GAS_LIMIT
   ```
   No fixed value is imposed on `h.gas_limit` by the execution layer (the mainnet genesis gas limit is 500,000,000).
4. `h.base_fee_per_gas == next_block_base_fee(p, h.timestamp)` (§2.4).
5. EIP-4844/EIP-7918 (Osaka): `h.excess_blob_gas == next_block_excess_blob_gas_osaka(p.excess_blob_gas, p.blob_gas_used, p.base_fee_per_gas)` with the Osaka blob parameters. Because no blob transactions exist, `blob_gas_used` is always 0 (§2.5) and this value is always 0.

> **Resolved conflict C-EXEC-02**: TIP-1010 (and the fee specification's parameter table) give the block gas limit as a fixed 500,000,000; the code enforces only the Ethereum ±1/1024 per-block bound above. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-02).

### 2.3 Gas-limit partition

```python
def shared_gas_limit(fork, gas_limit):
    return 0 if fork >= T4 else gas_limit // 10

def general_gas_limit(fork, gas_limit, shared_gas_limit):
    if chain_config.general_gas_limit is not None:   # genesis config "generalGasLimit"; absent on mainnet
        return chain_config.general_gas_limit
    if fork >= T1:
        return TEMPO_T1_GENERAL_GAS_LIMIT            # 30,000,000
    return (gas_limit - shared_gas_limit) // 2
```

On mainnet, with a 500,000,000 gas limit: T0 blocks have `shared_gas_limit = 50,000,000` and `general_gas_limit = 225,000,000`; T1–T3 blocks have `shared_gas_limit = 50,000,000` and `general_gas_limit = 30,000,000`; from T4 `shared_gas_limit = 0` and `general_gas_limit = 30,000,000`.

### 2.4 Base fee

The base fee of a block is a function of its parent header and the block's own fork (determined by the child's `timestamp`):

```python
def next_block_base_fee(parent, child_timestamp):
    fork = active_fork(child_timestamp)
    if fork >= T7:                                     # TIP-1067
        b, used, target, d = parent.base_fee_per_gas, parent.gas_used, 10_000_000, 8
        if used == target:
            nxt = b
        elif used > target:
            nxt = b + max(1, b * (used - target) // (target * d))
        else:
            nxt = saturating_sub(b, b * (target - used) // (target * d))
        return min(max(nxt, TEMPO_T7_BASE_FEE_FLOOR), TEMPO_T7_BASE_FEE_CAP)
    if fork >= T1:
        return TEMPO_T1_BASE_FEE                       # 20,000,000,000
    return TEMPO_T0_BASE_FEE                           # 10,000,000,000
```

Arithmetic is exact (at least 128-bit intermediates). `parent.gas_used` is the parent header's `gas_used` (sum of `tx_gas_used` over all lanes, §7). For the first T7 block the parent base fee is 20,000,000,000, so the result is clamped to `TEMPO_T7_BASE_FEE_CAP` regardless of `parent.gas_used`; this realises TIP-1067's activation seed.

Base fees are denominated in attodollars (10^-18 USD) per gas; conversion to fee-token units is specified in [06-transactions-and-fees.md](06-transactions-and-fees.md).

Reference implementation: crates/chainspec/src/spec.rs (`next_block_base_fee`, `shared_gas_limit_at`, `general_gas_limit_at`), crates/hardfork/src/constants.rs (`tempo_t7_next_block_base_fee`), crates/hardfork/src/lib.rs (`shared_gas_limit`, `general_gas_limit`).

### 2.5 Body checks before execution

1. `h.transactions_root` equals the root of the body's transaction list; `h.ommers_hash` equals the root of the (empty) ommers list.
2. The body carries a withdrawals list and `h.withdrawals_root` equals its root. The list MUST be empty (§4.1), so `h.withdrawals_root` MUST equal the empty-trie root `0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421`.
3. `h.blob_gas_used` equals the total blob gas of the body's transactions, which is always 0.
4. The RLP encoding of the whole block is at most `MAX_RLP_BLOCK_SIZE` bytes (EIP-7934).
5. System-transaction structure (before execution): see §5.5.1.

Reference implementation: crates/evm/src/consensus/mod.rs (`TempoConsensus`), reth `EthBeaconConsensus` and `reth_consensus_common::validation` at reth rev `966010c905449163ef161530a5ee95ac1e0c8487`.

---

## 3. Block execution pipeline

Given a block `B` with header `h`, its parent header `p` and the parent post-state `S`, a client MUST perform the following, in this order. Any failure makes `B` invalid.

```python
def execute_block(B, p, S):
    h = B.header
    fork = active_fork(h.timestamp)
    check_header(h, p)                     # §2.1–§2.4
    check_body_pre_execution(B)            # §2.5, §5.5.1
    env = block_env(h)                     # §1.5

    st = BlockState(
        section              = StartOfBlock,
        non_shared_gas_left  = saturating_sub(h.gas_limit, h.shared_gas_limit),
        non_payment_gas_left = h.general_gas_limit,
        incentive_gas_used   = 0,
        cumulative_gas_used  = 0,
        receipts             = [],
    )

    apply_pre_block_changes(S, B, fork)    # §4
    for tx in B.transactions:              # in body order
        process_transaction(S, st, tx, fork)   # §5
    requests = apply_post_block_changes(S, B, st, fork)   # §6
    check_post_execution(B, S, st, requests)              # §7
```

All state changes made by §4, §5 and §6 are part of the block's post-state and hence of `h.state_root`. System calls (§4.2, §4.3, §6.2, §6.3) produce no receipt, do not consume block gas and do not change `cumulative_gas_used`.

Reference implementation: crates/evm/src/block.rs (`TempoBlockExecutor`).

---

## 4. Pre-block state changes

`apply_pre_block_changes` performs, in order:

1. the withdrawals check (§4.1);
2. before T13, the inherited Ethereum pre-block system calls (§4.2); from T13, the TIP-1119 history call (§4.3);
3. the precompile marker installs (§4.5), in the order T2, T3, T5, T6, T7, T8;
4. from T10, the zone-factory install (§4.6);
5. from T13, the zone-runtime install (§4.7).

### 4.1 Withdrawals

If the block body's withdrawals list is non-empty, the block is invalid. (Together with §2.5 this means every block carries an empty withdrawals list.)

### 4.2 Ethereum pre-block system calls (before T13)

Before T13 the block executes the pre-block system calls Ethereum's Prague/Osaka execution layer executes, with Ethereum's parameters, regardless of whether code exists at the targets:

1. EIP-2935 history call (Prague is active and `h.number != 0`): system call (§4.4) with `caller = SYSTEM_ADDRESS`, `target = HISTORY_STORAGE_ADDRESS`, `gas = ETH_SYSTEM_CALL_GAS_LIMIT`, `data = h.parent_hash` (32 raw bytes). A revert or halt does not invalidate the block; its state changes are discarded.
2. EIP-4788 beacon-root call (Cancun is active): `h.parent_beacon_block_root` MUST be present. For `h.number != 0`: system call with `caller = SYSTEM_ADDRESS`, `target = BEACON_ROOTS_ADDRESS`, `gas = ETH_SYSTEM_CALL_GAS_LIMIT`, `data = h.parent_beacon_block_root` (32 raw bytes). A revert or halt does not invalidate the block; its state changes are discarded.

The mainnet genesis state contains no code at `HISTORY_STORAGE_ADDRESS` or `BEACON_ROOTS_ADDRESS`. As long as no code exists there, both calls are no-ops (§4.4). If code exists at a target (for example because it was deployed by a transaction), the call executes that code and commits its successful state changes; implementations MUST NOT skip these calls on the basis of the target's code.

### 4.3 TIP-1119 history call (from T13)

From T13, the executor MUST NOT perform the EIP-4788 call and MUST NOT require code at any target. It performs exactly one pre-block system call:

- If Prague is active and `h.number != 0`: system call with `caller = SYSTEM_ADDRESS`, `target = HISTORY_STORAGE_ADDRESS`, `gas = ETH_SYSTEM_CALL_GAS_LIMIT` (30,000,000), `data = h.parent_hash`. The returned state is committed. A revert or halt does not invalidate the block (its state changes are discarded); missing code produces no state change.

`h.parent_beacon_block_root` is still required to be present by §2.1 but is not read by execution from T13.

### 4.4 System-call semantics

A **system call** `(caller, target, data, gas)` executes one top-level message call with these properties:

- It is not a transaction: there is no signature, no nonce check or increment for `caller`, no intrinsic gas, no fee charging or settlement, no refund, no beneficiary payment, no receipt, and no effect on block gas or `cumulative_gas_used`.
- The message is a `CALL` from `caller` to `target` with `value = 0`, `gas = gas`, input `data`, `ORIGIN = caller`, `GASPRICE = 0`, in the block environment of §1.5 and with the EVM rules of §1 for the block's fork. `target` is warm at the start of the call. Tempo precompiles at `target` are dispatched as for any call ([precompiles/00-framework.md](precompiles/00-framework.md)).
- If `target` has no code (and is not a precompile), the call succeeds with empty output and changes no state (in particular it does not create the `target` or `caller` account).
- On success the call's state changes are committed. On revert or exceptional halt they are discarded; whether the block is then invalid depends on the call (stated per call).
- `caller`'s account is not modified by the call itself.

Reference implementation: alloy-rs/evm2 rev `a29a283f6cd4bc65e44f5813de5e9f43553c5fda` `crates/evm2/src/evm/system.rs` (`Evm::system_call`); reth rev `966010c905449163ef161530a5ee95ac1e0c8487` `crates/ethereum/evm/src/execution.rs` (`pre_execution_system_call_state_changes`); crates/evm/src/block.rs (`apply_pre_execution_changes`).

### 4.5 Precompile marker installs

For each of the following, if the fork is active for the block, the client MUST perform `install_marker(address)`, in table order:

| Fork | Address | Precompile |
|---|---|---|
| T2 | `0xCCCCCCCC00000000000000000000000000000001` | ValidatorConfigV2 |
| T3 | `0x5165300000000000000000000000000000000000` | SignatureVerifier |
| T3 | `0xFDC0000000000000000000000000000000000000` | AddressRegistry |
| T5 | `0x4D50500000000000000000000000000000000000` | TIP20ChannelReserve |
| T6 | `0xB10C000000000000000000000000000000000000` | ReceivePolicyGuard |
| T7 | `0x1060000000000000000000000000000000000000` | StorageCredits |
| T8 | `0xC077E00000000000000000000000000000000000` | CurrentCommittee |

```python
def install_marker(address, storage=()):
    acct = S.get_account(address)            # None if the account does not exist
    if acct is not None and acct.code_hash != KECCAK_EMPTY:
        return                               # any existing code: nothing to do
    acct = acct or Account(nonce=0, balance=0, storage={})
    acct.code = MARKER_CODE                  # b"\xef"; nonce, balance and existing storage are kept
    for (slot, value) in storage:
        acct.storage[slot] = value
    S.set_account(address, acct)
```

The install runs at the start of **every** block in which the fork is active; it changes state only the first time (or if the code were ever removed). The account is created if absent; after the install it is non-empty for EIP-161 purposes. The marker gives the precompile address non-empty code (so `EXTCODESIZE` is 1 and `EXTCODEHASH` is `keccak256(0xEF)`); precompile dispatch does not depend on it.

### 4.6 Zone-factory install (from T10)

From T10, at the start of every block:

```python
ZONE_FACTORY_ADDRESS     = 0x5AF2000000000000000000000000000000000000
ZONE_PORTAL_IMPL_ADDRESS = 0x5AD1000000000000000000000000000000000000
ZONE_VERIFIER_ADDRESS    = 0x5A56000000000000000000000000000000000000
ZONE_MESSENGER_ADDRESS   = 0x5A4D000000000000000000000000000000000000
INITIAL_FACTORY_OWNER    = 0xaF571FD4B3AD43a5807A5E58bFb25ea1aB327A14

def install_zone_factory():
    f = S.get_account(ZONE_FACTORY_ADDRESS)
    if f is not None and f.code_hash != KECCAK_EMPTY:
        return                                  # already installed (or allocated in genesis): no change at all
    slot0 = (INITIAL_FACTORY_OWNER_as_uint160 << 32) | 1
    # = 0x0000000000000000af571fd4b3ad43a5807a5e58bfb25ea1ab327a1400000001
    install_marker(ZONE_FACTORY_ADDRESS, storage=[(0, slot0)])
    install_runtimes(T10_ZONE_RUNTIMES)
```

`slot0` packs `1` in its low 32 bits and the initial owner in bits 32..191 (the meaning of these fields is specified in [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md)).

```python
def install_runtimes(runtimes):
    for (address, code) in runtimes:            # in the listed order
        acct = S.get_account(address)
        if acct is not None and acct.code_hash == keccak256(code):
            continue
        acct = acct or Account(nonce=0, balance=0, storage={})
        acct.code = code                        # replaces any existing code; nonce, balance, storage kept
        S.set_account(address, acct)
```

`T10_ZONE_RUNTIMES` is the following list. Each `code` is the exact runtime bytecode identified by its length and Keccak-256 hash:

| Address | Contract | Code length (bytes) | `keccak256(code)` |
|---|---|---|---|
| `ZONE_PORTAL_IMPL_ADDRESS` | ZonePortal implementation (T10) | 23,359 | `0x109c27a83ea58d7b91efcc7bb415a04abef5a52d8fdc5a246c96de965fa47b32` |
| `ZONE_VERIFIER_ADDRESS` | Zone verifier (T10) | 373 | `0xf3ab166b6d8637bb2f15ac5037b4546611339fc88e4b03b00b89559f7f2822a2` |
| `ZONE_MESSENGER_ADDRESS` | ZoneMessenger (T10) | 1,858 | `0x1ea2e80521c58fd7966e1fd370f84ac297261c7197f097ffc879de1890e0a1a0` |

### 4.7 Zone-runtime install (from T13)

From T13, at the start of every block (after §4.6), the client MUST perform `install_runtimes(T13_ZONE_RUNTIMES)`:

| Address | Contract | Code length (bytes) | `keccak256(code)` |
|---|---|---|---|
| `ZONE_PORTAL_IMPL_ADDRESS` | ZonePortal implementation (TIP-1096/TIP-1098) | 23,994 | `0xbb0c0e14d5c2e15ca4aa1aaeb8d5c7bfdcf35fdadac5380ff93d38f962e4c41e` |
| `ZONE_VERIFIER_ADDRESS` | Zone verifier (TIP-1096/TIP-1098) | 387 | `0xcf7b19d3c186e4fd235c94907d10bba5c1ce21d6e815676b00aaf298b456de14` |
| `ZONE_MESSENGER_ADDRESS` | ZoneMessenger (TIP-1096) | 1,858 | `0x526c5bb045b6229e5a693d70feee066cc3848b5f91c62949ced54818045214ee` |

Only code is replaced; storage, nonce and balance of these accounts are kept, and the zone factory account is not touched. This step is skipped when the chain's genesis timestamp already falls in T13 or later (the genesis allocation then carries these runtimes); on mainnet (genesis fork T0) it applies. It changes state only in the first T13 block.

From T13, `ZONE_VERIFIER_ADDRESS` is also a Tempo precompile address; calls to it are dispatched to the precompile ([precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md)) and the installed code is not executed by such calls.

> Note: the bytecodes themselves are published with the reference implementation (crates/contracts/src/zones.rs: `ZONE_PORTAL_RUNTIME`, `ZONE_VERIFIER_RUNTIME`, `ZONE_MESSENGER_RUNTIME`, `T13_ZONE_PORTAL_RUNTIME`, `T13_ZONE_VERIFIER_RUNTIME`, `T13_ZONE_MESSENGER_RUNTIME`). A conforming implementation MUST install byte strings with exactly the lengths and hashes above.

Reference implementation: crates/evm/src/block.rs (`deploy_precompile_at_boundary`, `deploy_zone_factory_at_boundary`, `install_zone_runtimes`, `upgrade_zone_runtimes`, `zone_runtime_fork`), crates/contracts/src/precompiles/zone_factory.rs, crates/contracts/src/precompiles/mod.rs.

---

## 5. Transaction loop

Transactions are processed strictly in body order. For each transaction:

```python
def process_transaction(S, st, tx, fork):
    is_system = is_system_tx(tx)                        # §5.5
    if is_system:
        check_system_tx(tx, fork)                       # §5.5.2
    elif tx.type == 0x76 and (tx.nonce_key >> 248) == TEMPO_SUBBLOCK_NONCE_KEY_PREFIX:
        raise InvalidBlock("subblock transactions are not supported")   # every fork
    payment = is_payment(tx, fork)                      # §5.3

    # Ethereum per-transaction block gas availability check.
    if min(tx.gas_limit, tx_gas_limit_cap(fork)) > h.gas_limit - st.cumulative_gas_used:
        raise InvalidBlock

    if is_system:
        result = execute_system_tx(S, tx)               # §5.5.3
    else:
        result = execute_tx(S, tx, fork)                # 06-transactions-and-fees.md
        # any transaction-validity failure raised by execute_tx makes the block invalid
    gas_used = result.tx_gas_used                       # §1.9; 0 for the system transaction

    next_section = section_after(st, is_system, payment, gas_used)     # §5.4, may raise
    commit(S, result.state_changes)
    st.cumulative_gas_used += gas_used
    st.receipts.append(Receipt(type=tx.type, success=result.success,
                               cumulative_gas_used=st.cumulative_gas_used, logs=result.logs))
    record_section(st, next_section, payment, gas_used)                # §5.4
```

Notes:

- `tx.nonce_key >> 248` is the most significant byte of the 256-bit `nonce_key`. Any type-`0x76` transaction whose `nonce_key` has most significant byte `0x5B` is invalid in a block at every fork, regardless of the rest of the transaction.
- A transaction that fails validation (as specified in [06-transactions-and-fees.md](06-transactions-and-fees.md)) makes the block invalid; a transaction that is valid but whose execution reverts or halts is included with `success = false` and its fee and other non-reverted effects as specified there.
- The block-gas check uses `cumulative_gas_used`, i.e. the sum of the `tx_gas_used` (after refunds and the EIP-7623 floor) of the preceding transactions, not their gas limits. Since a transaction with `gas_limit` above the cap is invalid anyway (§1.8), the check is equivalent to `tx.gas_limit <= h.gas_limit - cumulative_gas_used` for every valid transaction.
- The section check (§5.4) is evaluated **after** the transaction has executed, on its `tx_gas_used`.

Reference implementation: crates/evm/src/block.rs (`execute_transaction_without_commit`, `execute_transaction_with_commit_condition`, `commit_transaction`, `validate_tx_pre_execution`); reth `EthBlockExecutor::validate_transaction_gas_limit`.

### 5.1 Receipts

Every transaction in the block, including the pre-T4 system transaction, produces exactly one receipt with the fields:

| Field | Value |
|---|---|
| `tx_type` | the transaction's EIP-2718 type (`0x00`, `0x01`, `0x02`, `0x04` or `0x76`) |
| `success` | 1 if the transaction's execution succeeded, else 0 (EIP-658) |
| `cumulative_gas_used` | `st.cumulative_gas_used` after this transaction |
| `logs` | the logs of the transaction, in emission order (including logs emitted by protocol steps of transaction processing as specified in [06-transactions-and-fees.md](06-transactions-and-fees.md)) |

Tempo receipts carry no fee or gas-price fields. Their encoding (and the receipt bloom) is specified in [02-encoding.md](02-encoding.md). System calls (§4, §6) produce no receipts.

Reference implementation: crates/evm/src/block.rs (`TempoReceiptBuilder`).

### 5.2 Gas used per transaction

For all purposes of this chapter, a transaction's gas used is `tx_gas_used` from §1.9 (post-refund, post-floor). The system transaction's gas used is 0 (§5.5.3).

### 5.3 Payment classification

`is_payment(tx, fork)` is a pure function of the transaction payload (no state is read).

**Before T5 (v1).** Let `TIP20_PREFIX = 0x20C000000000000000000000` (12 bytes). An address `a` *has the TIP-20 prefix* iff its first 12 bytes equal `TIP20_PREFIX`.

```python
def is_payment_v1(tx):
    if tx.type in (0x00, 0x01, 0x02):
        return tx.to is not None and has_tip20_prefix(tx.to)     # contract creation -> False
    if tx.type == 0x04:
        return has_tip20_prefix(tx.to)
    if tx.type == 0x76:
        return all(c.to is not None and has_tip20_prefix(c.to) for c in tx.calls)
```

**From T5 (v2, TIP-1045).**

```python
KEY_AUTHORIZATION_MAX_RLP_LEN = 1024
MAX_PAYMENT_CALLDATA_LEN      = 2048

def is_payment_v2(tx):
    if tx.type == 0x00:
        return is_payment_call(tx.to, tx.input)
    if tx.type in (0x01, 0x02):
        return len(tx.access_list) == 0 and is_payment_call(tx.to, tx.input)
    if tx.type == 0x04:
        return (len(tx.access_list) == 0 and len(tx.authorization_list) == 0
                and is_payment_call(tx.to, tx.input))
    if tx.type == 0x76:
        return (len(tx.calls) > 0
                and len(tx.access_list) == 0
                and len(tx.tempo_authorization_list) == 0
                and (tx.key_authorization is None
                     or len(rlp(tx.key_authorization)) <= KEY_AUTHORIZATION_MAX_RLP_LEN)
                and all(is_payment_call(c.to, c.input) for c in tx.calls))

def is_payment_call(to, data):
    if to is None:                       # contract creation
        return False
    if has_tip20_prefix(to):
        return any(is_static_call(e, data) for e in TIP20_PAYMENT_ENTRIES)
    if to == TIP20_CHANNEL_RESERVE_ADDRESS:          # 0x4D50500000000000000000000000000000000000
        return (any(is_static_call(e, data) for e in CHANNEL_STATIC_ENTRIES)
                or any(is_dynamic_call(e, data) for e in CHANNEL_DYNAMIC_ENTRIES))
    return False

def is_static_call(e, data):
    # Only the selector and the exact length are checked; the argument words are not decoded.
    return data[0:4] == e.selector and len(data) == 4 + 32 * e.words

def is_dynamic_call(e, data):
    if data[0:4] != e.selector or len(data) > MAX_PAYMENT_CALLDATA_LEN:
        return False
    args = abi_decode_strict(e.signature, data[4:])   # None if it fails
    return args is not None and is_valid_tempo_signature_encoding(args.signature)
```

`rlp(tx.key_authorization)` is the RLP encoding of the signed key authorization exactly as it appears in the transaction ([02-encoding.md](02-encoding.md)). `is_valid_tempo_signature_encoding(b)` is true iff `b` parses as a Tempo primitive signature encoding ([03-signatures.md](03-signatures.md)); the signature is not verified. `abi_decode_strict` is Solidity-ABI decoding with validation: every value must be correctly encoded for its type (e.g. the high 12 bytes of an `address` word and the high 20 bytes of a `uint96` word are zero), offsets and lengths must be in range, and re-encoding the decoded values must reproduce `data[4:]` exactly.

Allow-list (`D` = `(address,address,address,address,bytes32,address,bytes32)`, the channel descriptor):

| Entry set | Signature | Selector | Words |
|---|---|---|---|
| `TIP20_PAYMENT_ENTRIES` | `transfer(address,uint256)` | `0xa9059cbb` | 2 |
| | `transferWithMemo(address,uint256,bytes32)` | `0x95777d59` | 3 |
| | `transferFrom(address,address,uint256)` | `0x23b872dd` | 3 |
| | `transferFromWithMemo(address,address,uint256,bytes32)` | `0x929c2539` | 4 |
| | `approve(address,uint256)` | `0x095ea7b3` | 2 |
| | `mint(address,uint256)` | `0x40c10f19` | 2 |
| | `mintWithMemo(address,uint256,bytes32)` | `0xe44f0b12` | 3 |
| | `burn(uint256)` | `0x42966c68` | 1 |
| | `burnWithMemo(uint256,bytes32)` | `0x38f23b0b` | 2 |
| `CHANNEL_STATIC_ENTRIES` | `open(address,address,address,uint96,bytes32,address)` | `0xedc53b00` | 6 |
| | `topUp(D,uint96)` | `0xdc48471e` | 8 |
| | `requestClose(D)` | `0x675402e5` | 7 |
| | `withdraw(D)` | `0x41e2c664` | 7 |
| `CHANNEL_DYNAMIC_ENTRIES` | `settle(D,uint96,bytes signature)` | `0x97fb5104` | dynamic |
| | `close(D,uint96,uint96,bytes signature)` | `0x73b57f74` | dynamic |

> **Resolved conflict C-EXEC-07**: TIP-1045 requires static-only payment calldata to satisfy the ABI encoding constraints of its signature and classifies malformed encodings as general; the code checks only the selector and exact length (e.g. an `address` word with non-zero high bytes still classifies as a payment). Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-07).

> **TODO**: `abi_decode_strict` above describes the validating decoder of `alloy-sol-types` (`abi_decode_validate`) used by the reference implementation for the two dynamic entries; its exact acceptance rules for edge cases (non-canonical offsets, padding of the `bytes` tail) should be cross-checked against that library before relying on this description for adversarial inputs.

The payment classification of the system transaction is irrelevant (§5.4).

Reference implementation: crates/primitives/src/transaction/envelope.rs (`is_payment_v1`, `is_payment_v2`, `is_tip1045_call`), crates/contracts/src/precompiles/tip20.rs (`is_payment`, `is_static_call`), crates/contracts/src/precompiles/tip20_channel_reserve.rs (`is_payment_with_valid_signature`), crates/evm/src/block.rs (`is_payment`).

### 5.4 Block sections and lane accounting

A block's transactions fall into consecutive **sections**. The executor tracks the current section and two lane budgets initialised from the header (§3): `non_shared_gas_left = saturating_sub(h.gas_limit, h.shared_gas_limit)` and `non_payment_gas_left = h.general_gas_limit`.

| Section | Meaning |
|---|---|
| `StartOfBlock` | no transaction processed yet (no start-of-block system transactions exist at any fork) |
| `NonShared` | the proposer's lane: payment and non-payment transactions within the lane budgets |
| `GasIncentive` | the gas-incentive section: every transaction after the first one that did not fit the lane budgets |
| `System` | after the end-of-block system transaction (pre-T4 only, §5.5) |

```python
def section_after(st, is_system, payment, gas_used):
    if is_system:
        if st.section == System:
            raise InvalidBlock("duplicate subblocks metadata system transaction")
        return System
    if st.section in (StartOfBlock, NonShared):
        if gas_used > st.non_shared_gas_left or (not payment and gas_used > st.non_payment_gas_left):
            return GasIncentive
        return NonShared
    if st.section == GasIncentive:
        return GasIncentive
    raise InvalidBlock("regular transaction can't follow system transaction")   # section == System

def record_section(st, nxt, payment, gas_used):
    st.section = nxt
    if nxt == NonShared:
        st.non_shared_gas_left -= gas_used
        if not payment:
            st.non_payment_gas_left -= gas_used
    elif nxt == GasIncentive:
        st.incentive_gas_used += gas_used
    # System: no lane gas is consumed
```

Rules that follow:

- `gas_used` is the transaction's `tx_gas_used` (§5.2), not its gas limit.
- Payment transactions consume only `non_shared_gas_left`; non-payment transactions consume both budgets.
- Once a transaction enters `GasIncentive`, every later regular transaction is in `GasIncentive` regardless of its type or gas, and no lane budget is checked for it; only the block gas limit (§5) constrains it. The gas of the incentive section is **not** bounded by `h.shared_gas_limit`.
- Before T4, a block with transactions in `GasIncentive` is valid.
- From T4, `shared_gas_limit = 0`; a block in which any transaction entered `GasIncentive` (`incentive_gas_used > 0` at the end of the transaction loop) is invalid (§6.1). Equivalently, from T4 every non-payment transaction must fit the remaining general budget and every transaction must fit the remaining non-shared budget.
- No regular transaction may follow the system transaction, and at most one system transaction may appear.

> **Resolved conflict C-EXEC-01**: TIP-1010 (invariant 5) and the payment-lane specification state that a block is invalid when non-payment gas exceeds `general_gas_limit` (or proposer-lane gas exceeds the non-shared limit, or subblock gas exceeds `shared_gas_limit`), and the payment-lane specification bounds post-lane inclusion by the shared budget; before T4 the code instead moves the overflowing transaction and all later ones into an unbounded `GasIncentive` section and accepts the block. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-01).

Reference implementation: crates/evm/src/block.rs (`BlockSection`, `next_section`, `record_committed_tx`, `finish_with_block_access_list`).

### 5.5 Pre-T4 subblock-metadata system transaction

A **system transaction** is a legacy (type `0x00`) transaction whose signature is exactly `r = 0`, `s = 0`, `y_parity = false`. Its sender is defined to be `0x0000000000000000000000000000000000000000` (no signature recovery is performed). Its encoding, and the encoding of `SubBlockMetadata`, are specified in [02-encoding.md](02-encoding.md).

#### 5.5.1 Structural checks before execution

1. Every system transaction in the block (at any position, at any fork) MUST satisfy: `gas_price == 0`, `gas_limit == 0`, `value == 0`, `nonce == 0` and `chain_id` present and equal to the chain id (4217), i.e. it is EIP-155-signed with `v = 2 * 4217 + 35 = 8469`.
2. Before T4: the block MUST contain at least one transaction and its **last** transaction MUST be a system transaction with `to == 0x0000000000000000000000000000000000000000` (a call, not a creation).
3. From T4: the block MUST NOT contain any system transaction (rule 2 does not apply; any system transaction is rejected by §5.5.2).

#### 5.5.2 Content checks (when the transaction is reached)

```python
def check_system_tx(tx, fork):
    if tx.to != Address(0):            # includes contract creation
        raise InvalidBlock("invalid system transaction")
    if fork >= T4:
        raise InvalidBlock("subblocks are disabled in T4+")
    data = tx.input
    if len(data) < 32:
        raise InvalidBlock("invalid subblocks metadata system transaction")
    metadata, number = data[:-32], data[-32:]
    if number != h.number.to_bytes(32, "big"):
        raise InvalidBlock("invalid subblocks metadata system transaction")
    items, rest = rlp_decode_list_of_SubBlockMetadata(metadata)   # 02-encoding.md
    if items is None or len(rest) != 0:
        raise InvalidBlock("invalid subblocks metadata system transaction")
```

Together with §5.4 (a system transaction moves the block into `System`, a second one or any later regular transaction is invalid) and §5.5.1, every pre-T4 block ends with exactly one system transaction, and no other system transaction appears.

#### 5.5.3 Execution

The system transaction is not processed by the ordinary legacy-transaction rules: there is no nonce check or increment, no intrinsic gas, no EIP-7825 cap check, no fee resolution, collection or settlement, and no account-creation charge. Instead:

1. Its `value` MUST be 0 and `to` MUST be a call (already guaranteed by §5.5.1/§5.5.2).
2. It executes as a system call (§4.4) with `caller = 0x0000000000000000000000000000000000000000`, `target = tx.to` (`0x0000…0000`), `data = tx.input`, `gas = TEMPO_SYSTEM_CALL_GAS_LIMIT` (250,000,000).
3. If the call does not succeed, the block is invalid. (The target has no code and is not a precompile, so the call is a no-op that succeeds and changes no state.)
4. Its `tx_gas_used` is 0 (gas spent and refund are forced to 0).
5. A receipt is appended (§5.1): `tx_type = 0x00`, `success = 1`, `cumulative_gas_used` unchanged from the previous receipt, no logs.

The subblock metadata it carries has no effect on execution state.

Reference implementation: crates/evm/src/consensus/mod.rs (`validate_block_pre_execution`), crates/chainspec/src/spec.rs (`SYSTEM_TX_COUNT`, `SYSTEM_TX_ADDRESSES`), crates/primitives/src/transaction/envelope.rs (`is_system_tx`, `is_valid_system_tx`, `TEMPO_SYSTEM_TX_SIGNATURE`), crates/evm/src/block.rs (`validate_system_tx`), crates/evm/src/handler/config.rs (`prepare_legacy`, `execute_legacy`).

---

## 6. Post-block state changes

After the last transaction, `apply_post_block_changes` performs, in order:

1. the T4 incentive check (§6.1);
2. from T8, the end-of-epoch committee call (§6.2);
3. before T13, the inherited Ethereum post-block processing (§6.3); from T13, nothing further (§6.4).

There are no block rewards, ommer rewards, withdrawal balance increments or DAO-fork changes at any fork.

### 6.1 Incentive check (from T4)

From T4: if `st.incentive_gas_used > 0`, the block is invalid.

### 6.2 End-of-epoch committee call (from T8)

From T8, if `(h.number + 1) % EPOCH_LENGTH == 0` (i.e. `h.number % EPOCH_LENGTH == EPOCH_LENGTH - 1`, the last block of an epoch; mainnet `EPOCH_LENGTH = 21_600`):

1. Read an `OnchainDkgOutcome` from the start of `h.extra_data` (format in [07-consensus.md](07-consensus.md) §10.2; embedded `Output` per [commonware/dkg.md §11.1](commonware/dkg.md#111-output)). This is a read, not a full decode, in the sense of [commonware/codec.md §11](commonware/codec.md#11-decoding-rules). If decoding fails, the block is invalid. (This step does not itself examine bytes after the encoded outcome.) For blocks that are not the last block of an epoch, `extra_data` MUST NOT be interpreted by this step.
2. Let `epoch = outcome.epoch` (`uint64`) and `publicKeys = [bytes32(k) for k in outcome.players]`, each player's 32-byte Ed25519 public key, in the outcome's player order (no sorting or deduplication).
3. Execute a system call (§4.4) with:
   - `caller = 0x0000000000000000000000000000000000000000`,
   - `target = CURRENT_COMMITTEE_ADDRESS` (`0xC077E00000000000000000000000000000000000`),
   - `gas = TEMPO_SYSTEM_CALL_GAS_LIMIT` (250,000,000),
   - `data = abi.encodeWithSelector(0x229bdd9c, epoch, publicKeys)`, i.e. `setCommitteeMembers(uint64,bytes32[])` ABI-encoded.
4. If the call reverts or halts, the block is invalid. Otherwise its state changes are committed.

The CurrentCommittee precompile accepts `setCommitteeMembers` only from `msg.sender == 0x0`, stores `epoch` and `publicKeys`, and performs these writes with TIP-1060 storage-credit accounting disabled (no credits are minted or consumed); see [precompiles/validator-config-and-zones.md](precompiles/validator-config-and-zones.md). The call produces no receipt and consumes no block gas. Because it runs after all transactions, transactions in the last block of epoch `E` observe the committee stored at the previous boundary.

The call runs after §6.1 and, before T13, before the Ethereum post-block calls of §6.3.

> **Resolved conflict C-EXEC-08**: TIP-1070 requires the committee update to be called "from the system address" following the EIP-4788 convention (conventionally `0xff…fe`); the code (and TIP-1119) call it from `0x0000…0000`, and the precompile rejects any other caller. Decided: this spec follows the implementation, and the TIP is amended in its own PR (tempoxyz/tempo#8940 to #8974). See [conflicts](conflicts.md#c-exec-08).

Reference implementation: crates/evm/src/block.rs (`apply_current_committee_system_call`), crates/precompiles/src/current_committee/mod.rs.

### 6.3 Ethereum post-block processing (before T13)

Before T13 the block computes execution requests as Ethereum Prague/Osaka does:

```python
def ethereum_post_block(receipts):
    requests = []
    # EIP-6110 deposits, parsed from receipt logs.
    deposits = b""
    for r in receipts:
        for log in r.logs:
            if log.address == DEPOSIT_CONTRACT_ADDRESS and log.topics[0:1] == [DEPOSIT_EVENT_TOPIC]:
                deposits += decode_deposit_event(log)   # pubkey ‖ withdrawal_credentials ‖ amount ‖ signature ‖ index
    requests.append((0x00, deposits))
    # EIP-7002 withdrawal requests.
    out = system_call(SYSTEM_ADDRESS, WITHDRAWAL_REQUEST_ADDRESS, b"", ETH_SYSTEM_CALL_GAS_LIMIT)
    if not out.success: raise InvalidBlock
    requests.append((0x01, out.output))
    # EIP-7251 consolidation requests.
    out = system_call(SYSTEM_ADDRESS, CONSOLIDATION_REQUEST_ADDRESS, b"", ETH_SYSTEM_CALL_GAS_LIMIT)
    if not out.success: raise InvalidBlock
    requests.append((0x02, out.output))
    return requests
```

- `DEPOSIT_CONTRACT_ADDRESS` is the chain's configured deposit contract: on mainnet `0x0000000000000000000000000000000000000000` (no account can emit logs from that address, so mainnet deposits are always empty). `DEPOSIT_EVENT_TOPIC = keccak256("DepositEvent(bytes,bytes,bytes,bytes,bytes)") = 0x649bbc62d0e31342afea4e5cd82d4049e7e1ee912fc0889aa790803be39038c5`; a matching log that fails to decode makes the block invalid.
- The EIP-7002 and EIP-7251 calls are made regardless of the targets' code. With no code at the target (the mainnet genesis state has none), the call succeeds with empty output and changes no state. If code exists, a revert or halt invalidates the block, and successful state changes are committed.
- The requests hash is computed per EIP-7685: `sha256(concat(sha256(type ‖ data) for (type, data) in requests if len(data) > 0))`. With all request data empty it equals `EMPTY_REQUESTS_HASH`.

Reference implementation: reth rev `966010c905449163ef161530a5ee95ac1e0c8487` `crates/ethereum/evm/src/execution.rs` (`block_requests_from_receipts`, `post_execution_system_call_state_changes`, `post_block_balance_state_changes`), `crates/ethereum/evm/src/executor.rs` (`finish_with_prepared_block_access_list`).

### 6.4 From T13 (TIP-1119)

From T13 the executor MUST NOT perform the EIP-7002, EIP-7251 (or EIP-8282) calls, MUST NOT parse deposit logs, and the execution-request list is empty, regardless of any code at those targets. Deposit-shaped logs remain ordinary receipt logs.

Reference implementation: crates/evm/src/block.rs (`finish_with_block_access_list`), tips/tip-1119.md.

---

## 7. Post-execution validation

After §6, the block is valid only if all of the following hold:

1. `h.gas_used == st.cumulative_gas_used` (the sum of `tx_gas_used` over all transactions; the system transaction contributes 0; system calls contribute nothing).
2. `h.receipts_root` equals the root of the receipt trie built from the block's receipts (§5.1) encoded per [02-encoding.md](02-encoding.md).
3. `h.logs_bloom` equals the bitwise OR of the blooms of all receipts.
4. `h.requests_hash` equals the EIP-7685 requests hash of the requests computed in §6.3 (before T13), or `EMPTY_REQUESTS_HASH` (from T13).
5. `h.state_root` equals the root of the post-state after all changes of §4, §5 and §6 ([04-state-and-genesis.md](04-state-and-genesis.md)).
6. `h.blob_gas_used == 0` (§2.5).

No block-access-list hash is computed or checked (Amsterdam is not active; §2.1).

Reference implementation: reth `crates/ethereum/consensus/src/validation.rs` (`validate_block_post_execution_with_bal_hashes`), crates/evm/src/consensus/mod.rs (`validate_block_post_execution`).

---

## 8. Rules that are NOT block-validity rules

The following limits are enforced by the reference transaction pool, payload builder or RPC only. A block containing transactions that violate them is still valid if it satisfies this specification; a follower MUST NOT reject blocks for violating them.

| Limit (reference value) | Where |
|---|---|
| At most 32 calls in a type-`0x76` transaction | pool |
| At most 128 KiB (131,072 bytes) of input per call | pool |
| At most 16 entries in `tempo_authorization_list` (default) | pool |
| Access list: at most 256 accounts, 256 storage keys per account, 2,048 storage keys in total | pool |
| Key authorization: at most 256 token limits; at most 64 call scopes, 64 selector rules per scope, 64 recipients per selector rule | pool (any limits enforced by the keychain precompile itself are specified in [precompiles/account-keychain.md](precompiles/account-keychain.md)) |
| `valid_after` at most 120 s in the future; `valid_before` at least 3 s in the future | pool (the block-validity time-window rule is in [06-transactions-and-fees.md](06-transactions-and-fees.md)) |
| Skipping the `valid_after` lower bound or the fee-AMM liquidity check | pool-only execution knobs; block execution MUST perform both checks as specified in [06](06-transactions-and-fees.md) |
| Use of the TIP-1045 classifier before T5 | pool and builder policy; consensus uses v1 before T5 (§5.3) |
| Choice of block gas limit (target), transaction ordering, how payment and non-payment transactions are packed, and stopping non-payment inclusion at `general_gas_limit` | builder policy (consensus rules are §2 and §5.4) |
| Block-access-list construction (EIP-7928) | performance only; not committed in headers |
| Parallel execution, storage-action replay and prewarming | performance only; results MUST equal sequential execution |

Reference implementation: crates/transaction-pool/src/validator.rs, crates/payload/builder/src/lib.rs.

---

## 9. Summary of execution changes by fork (this chapter)

| Fork | Mainnet activation (UTC timestamp) | Changes specified in this chapter |
|---|---|---|
| T0 | 0 (genesis) | Osaka base; base fee 1e10; shared = gas_limit/10; general = (gas_limit − shared)/2; tx cap 2^24; Prague precompiles; `0x4F` defined; payment classifier v1; mandatory end-of-block system transaction; Ethereum pre/post-block system calls |
| T1 | 1,770,908,400 | base fee 2e10; general gas limit 30,000,000; TIP-1000 gas parameters (§1.7) |
| T1A | 1,770,908,400 | tx gas cap 30,000,000 |
| T1B | 1,771,858,800 | — (transaction-level changes only, see 06) |
| T1C | 1,773,327,600 | Osaka precompile set (P256VERIFY, MODEXP changes); `0x4F` removed |
| T2 | 1,774,965,600 | ValidatorConfigV2 marker |
| T3 | 1,777,298,400 | SignatureVerifier and AddressRegistry markers |
| T4 | 1,779,112,800 | shared gas limit 0; incentive gas invalid; system transactions forbidden |
| T5 | 1,781,013,600 | TIP20ChannelReserve marker; payment classifier v2 (TIP-1045) |
| T6 | 1,782,223,200 | ReceivePolicyGuard marker |
| T7 | 1,783,605,600 | StorageCredits marker; TIP-1060 SSTORE hook, gas parameters and settlement; refund quotient 1; TIP-1067 dynamic base fee |
| T8 | 1,785,420,000 | CurrentCommittee marker; end-of-epoch committee call |
| T9 | 1,786,024,800 | — |
| T10 | 1,787,320,800 | zone factory and T10 zone runtimes install |
| T11 | 1,789,048,800 | — |
| T12 | 1,791,900,000 | — |
| T13 | 1,793,718,000 | TIP-1119 system-call selection (history call only, empty requests); T13 zone runtimes install |

The authoritative activation schedule is in [01-chain-and-forks.md](01-chain-and-forks.md).
