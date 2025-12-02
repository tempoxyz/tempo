# Sub-blocks
# Validator Shared Blockspace

## Abstract

This proposal allows non-proposing validators to propose a limited set of transactions in each block through signed **sub-blocks**. Sub-blocks are sent directly to the main proposer and their transactions are included in the block as described below. Consensus does not enforce inclusion. The proposer is incentivized to include sub-blocks by provisioning additional gas upon sub-block inclusion, which permits them to include additional transactions at the bottom of the block as described below. 


> NOTE:
> We currently allow only free transactions, i.e., transactions with `maxFeePerGas=0` in sub-blocks. Paid transactions will be allowed in a subsequent hard fork.


## Motivation

This proposal smooths access to blockspace across validators. It enables every validator to provide low-latency inclusion for themselves, their users, or their partners, without waiting for their turn as proposer.


## Specification

This specification describes the process in temporal order. 

### 0. Definitions

  * The gas limit of the whole block is `G`. There are `n` validators: 1 proposer and `n-1` other non-proposers. 
  * `f` fraction of the gas limit of the  block, `0 < f < 1` is reserved for the main proposer.


### 1. Sub-blocks
  * Each validator can construct a sub-block. Sub-blocks follow this structure:
```
sub-block = rlp([version, parent_hash, fee_recipient, [transactions], signature])
```
where:
* `version = 1`,
* `parent_hash` is the parent hash of the previous block.  
* `fee_recipient` is the EOA at which this validator wants to receive the fees included in this block. 
* `[transactions]` is an ordered list of transactions. Transactions in a sub-block must satisfy additional conditions described below in [Section 1.1](#11-sub-block-transactions). We explicitly allow for this list to be empty: a validator with no transactions to propose may still send a sub-block so that the proposer gets extra gas for the gas incentive region, described below. 
*  The `signature` field is the validator signing over a hash computed as  
`keccak256(magic_byte || rlp([version, parent_hash, fee_recipient, [transactions]]))`, 
where `magic_byte = 0x78`,  The signature ensures that this sub-block is valid only for the declared slot, and that the proposer cannot alter the order or set of transactions included in a sub-block. 
* The validator sends this sub-block directly to the next proposer. 


For each validator `i`, define 
   
   `unreservedGas[i] = (1 - f) * G / n - Σ(gasLimit of transactions in sub-block[i])`
   
#### 1.1 Sub-block Transactions

We use the two-dimensional nonce sequence to simplify transaction validity. Recall that in this construction, a nonce is a `uint256` value, where the first 192 bits are the `sequence key` and the remaining 64 bits are treated as sequential incrementing nonces (see [Porto Docs](https://porto.sh/contracts/account#nonce-management)).

Let `validatorPubKey` be the public key of the validator proposing a given sub-block. Let `validatorPubKey120` be the most significant 120 bits of the validator's public key. 

We reserve sequence keys to each validator by requiring that the first (most significant) byte of the `sequence key` is the constant byte `0x5b`, and the next 15 bytes (120 bits) encode `validatorPubKey120`. 

Formally, we require that:

1. The `sequence key` of any transaction in the sub-block is of the form `(0x5b << 184) + (validatorPubKey120 << 64) + x`, where `x` is a value between `0` and `2**64 - 1`. In other words, the most significant byte of the sequence key is always `0x5b`, the next 15 bytes are the most significant 120 bits of the validator's public key, and the final 8 bytes still allow for 2D-nonces.

2. No two validators share the same `validatorPubKey120`; each validator's reserved space is distinct.

This explicit prefixing with `0x5b` ensures the reserved sequence key space is unambiguous and disjoint across validators. Sub-block proposers control all sequence keys of the form above, and can ensure that nonces are sequential within their space.  

### 2. Block Construction

The proposer collects sub-blocks from other validators. It now constructs a block with the following contents:

```
transactions = [list of own transactions] | [sub-block transactions] | [gas incentive transactions]
```

  * `list of own transactions` are regular transactions from the proposer with `f * G` gas limit. 
  * `sub-block transactions` are transactions from the included sub-blocks. **This includes a sub-block from the proposer itself if the proposer desires.** Nonce sequence keys with prefix  `0x5b` should only appear in this section. 
  * `gas incentive transactions` are additional transactions that the proposer can include after the sub-block transactions, with additional gas defined below.

We have the following new **header field**:
```
shared_gas_limit  // The total gas limit allocated for the sub-blocks and gas incentive transactions
```

#### 2.1 System transaction

The block includes a **new system transaction**, whose call data contains, for each included sub-block, the public key of the validator proposing, the `feeRecipient` for that sub-block and the signature of the sub-block. It is a no-op, and is there for execution layer blocks to be self-contained/carry all context. 

| Field                                | Value / Requirement                                                                                          | Notes / Validation                                                                                                  |
|--------------------------------------|---------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------|
| **Type**                              | Legacy transaction                                                                                            |                                                            |
| **Position in Block**                 | **Last transaction**                                                                                          | Block is **invalid** if absent.                                                                          |
| **From (sender)**                     | `0x0000000000000000000000000000000000000000`                                                                  | Zero address                                                                                           |
| **To (recipient)**                    | `0x0000000000000000000000000000000000000000`                                                                                 | No-op                                                                 |
| **Calldata**                          | `rlp([[version, validator_pubkey, fee_recipient, signature], ...])`                                                                |  Sub-block version (currently = 1), each included sub-block's validator public key, feeRecipient, and signature.                                                                                               |
| **Value**                             | `0`                                                                                                           | No native token transfer.                                                                                             |
| **Nonce**                             | 0                                                                |                                                                             |
| **Gas Limit**                         | 0                                                           | Does **not** contribute to block gas accounting.                                                                      |
| **Gas Price**                         | 0                                                    | Independent of block base fee; does not pay fees.                                                                     |
| **Signature**                         | `r = 0`, `s = 0`, `yParity = false`                                                                           | Empty signature designates system transaction.                                                                        |




### 3. Proposer Behavior

* Construct Main Block in the usual way.
* Collect sub-blocks from validators, including from self. Verify signatures and gas bounds of sub-blocks. Skip (i.e., do not include) invalid or missing sub-blocks; include valid ones. Transactions from a sub-block must be contiguous in the block, but sub-blocks can be included in any order. 
* Compute proposer Gas Incentive section limit:
  ```
  gasIncentiveLimit =  Σ(unreservedGas[i]) for all included sub-blocks [i]
  ```
* Append transactions at the bottom up to this gas limit. 
* Construct and include the [system transaction](#21-system-transaction) before the fee-AMM system transaction. 


#### 3.1 Proposer Incentives

  * We do not enforce censorship-resistance for the transactions at consensus layer. 
  * Proposer is incentivized by additional gas from sub-blocks included and reciprocity. 
  * Additional gas is unrestricted so it could include backruns etc from sub-block transactions. 

### 4. Block Validity Rules:

  1. Gas Limits: 
      *`[list of own transactions]` uses gas at most `f * G`. 
      * Each sub-block uses at most its gas limit: `Σ(gasLimit of transactions in sub-block[i]) <= (1-f) * G / n`.
      * `[gas incentive transactions]` use total gas `<= gasIncentiveLimit`.
      * General transactions gas limit from payments lane spec applies to `[list of own transactions]`. 
  2. Transactions with nonce sequence key prefix `0x5b` appear only in the `[sub-block transactions]`. Transactions are contiguous by validator. 
  The `[list of own transactions]` and `[gas incentive transactions]` can use any un-reserved `sequence key`. 
  3. [System transaction](#21-system-transaction) is present, in the correct position, and valid (matches contents of the block). 


### 5. Consensus Behavior

  1. Proposer constructs and propagates the block as described above, along with all included sub-blocks as additional context.
  2. Validators attest to a block when **all** the block validity conditions above are satisfied. 
    

 ### 6. Transaction Fee Accounting

  To be added when we enable general transactions. 
  
