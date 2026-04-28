# Subblocks v3: Proposed Design

*Draft for discussion — not a specification*

## Problems with Subblocks v2

Subblocks v2 ([TIP-1019](https://github.com/tempoxyz/tempo/pull/2434)) introduced builder delegation, many-to-one validator-to-builder mapping, and ed25519 per-machine signing. However, it has three limitations rooted in its all-or-nothing execution model:

### 1. Root-key-only signing

Subblock transactions must be signed with the user's root EOA key. Keychain (access key) signatures are banned because of a race condition:

- User signs a subblock tx with an access key
- Builder validates and includes it in a subblock
- In the same block, a main block tx revokes that access key
- Main block txs execute first, then subblock txs
- The subblock tx executes with a revoked key

Since v2 has no mechanism to exclude individual transactions from a subblock after signing, the builder faces a bad choice: include the subblock with the now-invalid transaction (which would make the entire block invalid due to a failed signature verification), or exclude the entire subblock. The only alternative was to ban keychain signatures entirely. This forces users to use their root key for all subblock transactions, which is a significant UX limitation — users cannot use access keys with spending limits, session keys, or delegated signers for fast-path transactions.

### 2. No overflow beyond gas budget

A subblock builder's gas budget is `per_validator_gas × gas_weight`. If the subblock builder has more transactions than fit in their budget, the excess transactions are simply held until the next block. There is no mechanism for the subblock builder to forward overflow transactions to the proposer for optional inclusion using available gas (e.g., the gas incentive lane).

This leaves throughput on the table: the proposer may have unused gas capacity, and the subblock builder has transactions ready to fill it, but there's no channel between them within the subblock protocol.

### 3. Fee failure requires noop + nonce increment

When a subblock transaction cannot pay its fees (e.g., the user's balance was drained by a main block transaction, or the FeeAMM lacks sufficient liquidity for the fee token swap), the transaction becomes a **noop** — it does nothing but the nonce is still incremented. This is necessary in v2 because removing the transaction would invalidate the builder's signature over the subblock.

This has undesirable consequences:
- The user's nonce is polluted (incremented for a transaction that did nothing)
- Gas budget is consumed by a transaction that produced no useful work
- The "noop but increment nonce" semantics are unintuitive and complicate client implementations

## Desiderata

Building on the foundation of v2 (builder delegation, many-to-one mapping, ed25519 per-machine signing), a v3 design should additionally:

1. **Allow keychain signatures** — users can sign subblock transactions with access keys, session keys, or any authorized signer, not just the root EOA
2. **Support overflow** — builders can propose more transactions than fit in their gas budget; the proposer can optionally include the overflow using available gas
3. **Clean fee failure handling** — transactions that cannot pay fees are excluded cleanly, with no nonce increment and no noop execution
4. **Preserve builder signature integrity** — the builder signs a full proposed bundle; the proposer selectively executes a subset without breaking the signature
5. **Maintain consensus verifiability** — all nodes can independently verify that the proposer's inclusion/exclusion decisions were correct

## Design Overview

### Block structure

The block structure changes from a flat transaction list to a structured format:

```
Block = [
    main_block_txs,          // proposer's own transactions
    subblock_1_txs,          // builder 1's proposed transactions
    subblock_2_txs,          // builder 2's proposed transactions
    ...
    metadata_system_tx       // inclusion decisions for each subblock
]
```

Each subblock section contains the **full set of transactions proposed by the builder** — including transactions that will not be executed. The metadata system transaction specifies which transactions from each subblock are actually included for execution.

### Metadata and inclusion decisions

The metadata system transaction (last in the block) contains, for each subblock:

- **Builder identity**: address, ed25519 signer, signature over the full proposed subblock
- **Executed prefix**: the first N transactions from the subblock that are executed (N ≤ total proposed)
- **Exclusions within the prefix**: indices of specific transactions within the prefix that are excluded from execution

This gives the proposer two tools:

1. **Truncation** — the proposer can cut the subblock to a prefix of any length. Transactions after the prefix are not executed. This handles overflow: the builder proposes as many transactions as they have, the proposer executes up to the gas budget and truncates the rest (or includes more if they have available gas).

2. **Exclusion** — within the executed prefix, the proposer can exclude individual transactions that would fail. This handles fee failures, key revocations, and nonce conflicts. Excluded transactions are not executed: no state changes, no nonce increment, no fee payment.

### Execution model

Block execution proceeds in order:

1. **Main block transactions** execute normally
2. **For each subblock**, in the order specified by the proposer:
   - For each transaction in the executed prefix:
     - If the transaction is marked as excluded in metadata: skip it entirely (no state change)
     - Otherwise: execute it, with `block.beneficiary` temporarily set to the builder address for fee routing
3. **Metadata system transaction** is processed:
   - Verify ed25519 signatures for each subblock (against the full proposed transaction list, including excluded and truncated transactions)
   - Verify each exclusion is justified (the transaction would genuinely have failed)
   - Verify gas budget constraints

### Exclusion verification

For each excluded transaction, validators must independently confirm the exclusion was justified. Valid exclusion reasons:

- **Nonce failure**: the transaction's nonce does not match the expected on-chain nonce at the point of execution (e.g., a main block transaction incremented the sender's nonce)
- **Fee payment failure**: the sender cannot pay fees (e.g., balance drained by a prior transaction in the block)
- **Key revocation**: the transaction was signed with a keychain key that was revoked by a prior transaction in the block

The full transaction data for excluded transactions is available in the block (they are part of the subblock section), so validators have everything they need to re-check.

Exclusions that cannot be justified invalidate the block — the proposer cannot arbitrarily censor transactions from a builder's subblock.

### Overflow and gas budget

The builder's gas budget (`per_validator_gas × gas_weight`) is a **floor guarantee**, not a ceiling:

- The proposer MUST execute at least the gas budget worth of transactions from the subblock (minus justified exclusions)
- The proposer MAY execute additional transactions beyond the gas budget if they have available gas (e.g., from the incentive lane)
- The proposer MAY truncate any transactions beyond the gas budget (no obligation to include overflow)

Builders are free to propose subblocks larger than their gas budget. The proposer decides how much overflow to include.

### Fee routing

Fee routing remains metadata-driven via the existing FeeManager:

- For all executed subblock transactions (within or beyond the gas budget), `block.beneficiary` is temporarily set to the builder address
- `FeeManager.validatorTokens[builder]` determines the builder's preferred fee token
- No changes to FeeManager are needed

### Keychain signature support

With the exclusion mechanism, keychain signatures are safe in subblocks:

- A user signs a subblock tx with an access key and submits it to the builder
- The builder includes it in the subblock
- If a main block tx revokes that access key, the proposer detects this and excludes the transaction
- Validators verify: the key was indeed revoked, so the exclusion is justified
- The user's expectation ("key revocation is immediate") is preserved — the transaction simply doesn't execute, and no nonce is incremented

The root-key-only restriction from v2 is removed entirely.

## What this enables

| Capability | v2 | v3 |
|-----------|----|----|
| Keychain/session key signatures in subblocks | ✗ | ✓ |
| Builder proposes more txs than gas budget | ✗ | ✓ |
| Fee failure without nonce pollution | ✗ | ✓ |
| Proposer includes overflow on space-available basis | ✗ | ✓ |
| Clean exclusion of invalid txs | ✗ | ✓ |

## Design Rationale

### Why subblocks retain the `0x5b` nonce key

- The `0x5b | builder_address | nonce_remainder` nonce key **binds each transaction to a specific subblock builder**. Without this, the proposer could pluck high-fee transactions out of a subblock and include them in the main block, keeping the fees.
- A `0x5b` transaction can only route fees to the builder address encoded in its nonce key — the proposer gains nothing by moving it.
- This is why non-Tempo transactions (standard EIP-1559, etc.) are not supported in subblocks: they have no builder address binding, so the proposer could freely re-route their fees.

### Why subblocks need to be a struct in the block

- An alternative is "builder codes" — the builder submits individual transactions and the proposer picks and chooses. But this gives the proposer full discretion to cherry-pick, reorder, or censor. Subblocks give the builder a bundle guarantee: the proposer includes it (with justified exclusions) or doesn't.
- Subblocks must be a distinct struct rather than a range in a flat tx list because they can contain transactions that are not executed. Invalid transactions cannot appear in a flat transaction list — every node would reject them.
- The subblock struct separates "proposed" from "executed": the full proposed bundle lives in the block, and the metadata declares which transactions are actually executed.
- This ensures consensus verifiability: every validator has the full proposed data in the block and can independently verify that each exclusion is justified.
