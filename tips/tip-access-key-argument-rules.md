---
id: TIP-XXXX
title: Access Key Argument Rules
description: Lets an access key pin any fixed-position address argument of a call to an allowlist or to the account itself.
authors: Kartik Patel
status: Draft
related: TIP-1011, TIP-1144, TIP-1167
protocolVersion: TBD
---

# TIP-XXXX: Access Key Argument Rules

## Abstract

This TIP extends TIP-1011 selector rules with argument rules. An argument rule pins one fixed-position ABI address argument of a call to an allowlist, or requires it to equal the account the key belongs to. Rules work on any target and selector. They only read the ABI head, so values inside `bytes`, arrays and encrypted payloads stay out of reach.

## Motivation

TIP-1011 recipient rules check ABI argument 0, and only for TIP-20 `transfer`, `approve` and `transferWithMemo`. Any other call a scoped key makes can send value to an address the key picks:

- **Stablecoin DEX swaps:** a key can call `swapExactAmountIn` with any `tokenIn` and `tokenOut`.
- **Vaults:** `deposit` and `withdraw` take a `receiver` and `owner` the key chooses.
- **Zone withdrawals:** in `requestWithdrawal`, argument 0 is `token`. The key chooses `to` (argument 1) and `zoneFallbackRecipient` (argument 5).

Apps that need these controls keep keys in off-chain signer services whose policies decode top-level calldata and compare typed arguments. This TIP moves that check into the protocol for the common case: typed address arguments in the ABI head.

Alternatives considered:

- **Policy contracts (TIP-1161).** More expressive, but each use case needs a deployed, maintained contract, and every scoped call pays for an external call.
- **Purpose-built functions** with the constrained argument at position 0. Each one needs a new interface per protocol, and the keychain still has to list each selector.
- **Nested decoding** of `bytes` arguments. It would make the keychain an ABI decoder and still can't read encrypted payloads. Flows that carry destinations in `bytes` should take them from the protocol instead (TIP-1167).

## Assumptions

- Amounts are enforced by spending limits at runtime, including Zone withdrawals (TIP-1144). Argument rules never bound amounts.
- A pinned target is trusted to do what its code says. Pinning `to` to a router only helps if the router takes no destinations from the signer.
- Scope checks run on each top-level call the key makes, as in TIP-1011. Calls made by the target are not checked.

---

# Specification

## Overview

An **argument rule** names an ABI head word by index and a constraint on it. A selector rule may carry several argument rules; a call matches the selector rule only if every argument rule passes. The existing `recipients` field keeps its meaning and its TIP-20-only scope.

## Mechanics

### Data structures

```text
ArgRule {
    index: u8,              // ABI head word: calldata[4 + 32*index .. 36 + 32*index]
    kind: InList | IsAccount,
    values: Vec<address>,   // InList: allowed addresses. IsAccount: empty.
}

SelectorRule {
    selector: bytes4,
    recipients: Vec<address>,  // unchanged
    arg_rules: Vec<ArgRule>,   // new, [] => no argument checks
}
```

### Authorization checks

A key authorization or scope update MUST be rejected if any selector rule has:

1. More than `MAX_ARG_RULES` argument rules, or two rules with the same `index`.
2. An `InList` rule with no values, more than `MAX_ARG_VALUES` values, a zero address or a duplicate.
3. An `IsAccount` rule with values.
4. Argument rules on a target scope with `selector_rules = []`.

Argument rules are allowed on any target and selector. The TIP-20 restriction applies only to `recipients`.

### Call checks

For a top-level call that matched a selector rule with argument rules, for each rule:

1. If `calldata.length < 36 + 32*index`, the call fails the scope check.
2. Read word `w = calldata[4 + 32*index .. 36 + 32*index]`. If its top 12 bytes are not zero, the call fails.
3. Let `a` be the low 20 bytes. `InList` passes if `a` is in `values`. `IsAccount` passes if `a` equals the account that authorized the key.

A failed check behaves exactly like any other TIP-1011 scope failure.

### Storage

Argument rules are stored under the selector scope and removed with it. Replacing a target's scope replaces its argument rules.

### Activation

Active from the hardfork that adopts this TIP, in both the Tempo and Zone keychains. Before activation, authorizations carrying `arg_rules` are rejected.

## Interfaces

```solidity
enum ArgKind { InList, IsAccount }

struct ArgRule {
    uint8 index;
    ArgKind kind;
    address[] values;
}

struct SelectorRule {
    bytes4 selector;
    address[] recipients;
    ArgRule[] argRules;
}
```

The RLP `KeyAuthorization` encoding gains `arg_rules` as a trailing optional field of each selector rule.

### Examples

| Use case | Target, selector | Argument rules |
|---|---|---|
| Swap only into one stablecoin | Stablecoin DEX, `swapExactAmountIn` | `{0, InList, [pathUSD, USDC.e, USDT]}`, `{1, InList, [oUSD]}` |
| Vault deposits stay with the account | Vault, `deposit(uint256,address)` | `{1, IsAccount}` |
| Zone withdrawal through one router | Zone outbox, `requestWithdrawal` | `{0, InList, [token]}`, `{1, InList, [router]}`, `{5, IsAccount}` |

# Compatibility

Existing keys and authorizations are unchanged. SDKs need to encode the new field and SHOULD build argument rules from named presets per function, not raw indexes.

# Observability

N/A. Scope failures already surface as TIP-1011 call-scope errors.

# Threat Model

- **Leaked key:** can still make any call its scope allows, with any value in arguments that carry no rule, up to its spending limits.
- **Wrong index:** a rule on the wrong word pins the wrong field and leaves the intended one open. Presets mitigate this.
- **Fields inside `bytes` or encrypted payloads:** out of scope. Flows that need them pinned must take destinations from the protocol (TIP-1167).
- **Trusted targets:** a pinned contract that forwards value to a signer-chosen address defeats the rule.

# Invariants

1. A call passes only if every argument rule of its selector rule passes.
2. A word with non-zero top 12 bytes never passes a rule.
3. `IsAccount` passes only for the authorizing account.
4. Selector rules without argument rules behave exactly as in TIP-1011.
5. Removing a selector or target removes its argument rules.

