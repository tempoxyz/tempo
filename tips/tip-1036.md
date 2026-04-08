---
id: TIP-1036
title: T2 Hardfork Bug Fixes
description: Meta TIP collecting all audit-driven bug fixes and hardening changes gated behind the T2 hardfork.
authors: Tanishk (@legion2002), Rusowsky (@0xrusowsky), Jennifer (@jenpaff), Howy (@howydev), Kitsune (@0xKitsune)
status: In Review
related: N/A
protocolVersion: T2
---

# TIP-1036: T2 Hardfork Bug Fixes

## Abstract

This meta TIP collects audit-driven bug fixes, security hardening, and correctness updates that activate at T2. Each item is small in isolation, but together they define the complete in-scope T2 bug-fix bundle for this TIP, while fixes already specified by other activated TIPs (such as TIP-1017) are intentionally excluded.

## Motivation

Internal and external review uncovered several T2-relevant correctness and security issues across core execution paths. Because these fixes alter state-function behavior at activation boundaries, they need hardfork gating and are grouped here as one coordinated rollout. This meta TIP tracks only fixes that are not already specified by another activated TIP (for example, TIP-1017).

---

# Changes

## 1. Require `tx.origin` for AccountKeychain admin ops

**PRs**: [#3202](https://github.com/tempoxyz/tempo/pull/3202) · **Author**: @legion2002, [#3250](https://github.com/tempoxyz/tempo/pull/3250) · **Author**: @0xrusowsky

With T2, `authorizeKey`, `revokeKey`, and `updateSpendingLimit` require direct owner calls by enforcing both `transaction_key == Address::ZERO` and `msg_sender == tx_origin`. This blocks indirect contract-call paths from being used to perform key-admin actions with owner-level authority. If `tx_origin` is not seeded, admin ops are rejected (failed-closed).

## 2. Reject self-sponsored fee payer signatures

**PR**: [#3200](https://github.com/tempoxyz/tempo/pull/3200) *(merged)* · **Author**: @legion2002

Rejects AA transactions where the `fee_payer_signature` resolves back to the sender, preventing self-sponsored signatures from bypassing fee-payer assumptions. Enforced in both txpool validation and EVM fee-payer resolution.

## 3. Check token paused in internal DEX balance swaps

**PR**: [#3204](https://github.com/tempoxyz/tempo/pull/3204) · **Author**: @0xrusowsky

Adds a `check_not_paused()` call in `StablecoinDEX` internal balance transfers gated behind `is_t2()`. Previously, swaps using internal DEX balances could bypass the token pause state.

## 4. Correct built-in policy type data for TIP403Registry

**PR**: [#3203](https://github.com/tempoxyz/tempo/pull/3203) *(merged)* · **Author**: @0xrusowsky

Built-in policies (`REJECT_ALL` / `ALLOW_ALL`) are virtual and not stored on-chain. On T2, `policyData()` now returns the correct `PolicyType` (`WHITELIST` / `BLACKLIST` respectively) and `Address::ZERO` admin for these built-in IDs instead of falling through to storage reads.

## 5. Reject legacy invalid policy types in compound sub-policies

**PR**: [#3188](https://github.com/tempoxyz/tempo/pull/3188) *(merged)* · **Author**: @howydev

Uses `is_simple()` instead of `!is_compound()` to validate compound policy sub-policies, rejecting legacy type-255 policies that previously passed the negated check.

## 6. Handle T2 policy errors in DEX

**PR**: [#3015](https://github.com/tempoxyz/tempo/pull/3015) *(merged)* · **Author**: @0xrusowsky

Updates DEX precompiles to handle the new `TIP403RegistryError::InvalidPolicyType` error returned by `policy_type()` post-T2, replacing the old `Panic(UnderOverflow)` sentinel.

## 7. Return zero remaining limit for revoked keys

**PR**: [#2553](https://github.com/tempoxyz/tempo/pull/2553) *(merged)* · **Author**: @0xrusowsky

`getRemainingLimit()` now returns zero for revoked or non-existent access keys instead of a stale positive value.

## 8. Nonce key gas repricing

**PR**: [#2533](https://github.com/tempoxyz/tempo/pull/2533) *(merged)* · **Author**: @0xrusowsky

Increases intrinsic gas costs for 2D nonce keys on T2 by adding `2 × WARM_SLOAD` to both existing-key and new-key gas to account for extended storage lookups. Base costs differ (`COLD_SLOAD + WARM_SSTORE_RESET` for existing, `COLD_SLOAD + SSTORE_SET` for new), but the T2 delta is the same.

## 9. Error with `PolicyNotFound` for non-existent policy IDs

**PR**: [#2618](https://github.com/tempoxyz/tempo/pull/2618) *(merged)* · **Author**: @0xrusowsky

`get_policy_data()` now reverts with `PolicyNotFound` for non-existent policy IDs instead of silently returning default values.

## 10. Refund spending limit for unused gas fees

**PR**: [#2528](https://github.com/tempoxyz/tempo/pull/2528) *(merged)* · **Author**: @legion2002

Restores access key spending limits by the refunded gas amount in `transfer_fee_post_tx()`. Previously the full max fee was permanently deducted from the spending limit regardless of actual gas used.

## 11. Tick spacing checks on DEX price conversion functions

**PR**: [#2513](https://github.com/tempoxyz/tempo/pull/2513) *(merged)* · **Author**: @0xKitsune

Adds tick spacing validation to `tick_to_price` and `price_to_tick`, rejecting ticks that don't align with the pool's configured spacing.

## 12. Reserved liquidity transient storage check

**PR**: [#2496](https://github.com/tempoxyz/tempo/pull/2496) *(merged)* · **Author**: @0xKitsune

Adds a transient storage (`TSTORE`/`TLOAD`) guard to prevent reserved liquidity from being double-spent within the same transaction.

## 13. Reject zero-address ecrecover in permit

**PR**: [#2786](https://github.com/tempoxyz/tempo/pull/2786) *(merged)* · **Author**: @howydev

`permit()` now explicitly rejects `recovered == address(0)` before comparing against `owner`. Previously, a crafted signature recovering to `address(0)` could have been accepted if `owner` was also `address(0)`.

