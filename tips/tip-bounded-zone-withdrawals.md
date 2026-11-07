---
id: TIP-XXXX
title: Bounded Zone Withdrawals for Access Keys
description: Lets an access key pin a Zone withdrawal's recipient, charges withdrawals against the key's spending limit once, and returns callback change or outputs to the account through the existing bounce-back path.
authors: Kartik Patel
status: Draft (initial proposal, unnumbered)
related: TIP-1011, TIP-1006, TIP-1161
protocolVersion: TBD
---

# TIP-XXXX: Bounded Zone Withdrawals for Access Keys

## Abstract

A Zone access key that may call `ZoneOutbox.requestWithdrawal` can withdraw the account's whole Zone balance to any address. This TIP bounds such a key with three changes to mechanisms Tempo already has: a TIP-1011 recipient rule on `requestWithdrawal`, a spending-limit charge on every withdrawal, and a return path that sends a callback's change or output to the withdrawal's fallback recipient. The user still signs one key authorization. The main limitation is that a key bounded to a receiver, such as a router, is only as safe as that receiver's own checks on where it pays.

## Motivation

Integrators hold access keys on users' Zone accounts to pay from Zone balances: a card issuer settling card spends through a Zone router, or a wallet backend moving funds into Earn, Tempo's yield vaults. Zones run no user contracts, so an access key on the user's account is the only way to do this.

Background, from the existing protocol:

- **Access keys (TIP-1011).** An account authorizes an access key with spending limits per token and a call scope: the targets and function selectors the key may call. For TIP-20 `transfer`, `approve` and `transferWithMemo`, a selector rule may also list allowed recipients, which the keychain (the precompile that stores and checks keys) compares with the call's first argument.
- **Withdrawals.** A Zone withdrawal is `requestWithdrawal(token, to, amount, memo, gasLimit, zoneFallbackRecipient, data, revealTo)`. `to` is the Tempo recipient: an account for a plain withdrawal, or a contract that receives a callback when `gasLimit > 0`. `data` is the callback's input; `memo` and `revealTo` do not affect this TIP.
- **Fallback recipient and bounce-back.** The outbox stores `zoneFallbackRecipient` on the Zone under a per-withdrawal `fallbackNonce`, so Tempo never sees it. If Tempo-side processing fails, the portal queues a bounce-back: a deposit back to the Zone that names only the nonce, token and amount. The Zone resolves the nonce and credits the fallback recipient.
- **Returns today.** A callback receiver, such as a Zone router, that sends funds back to the Zone calls `ZonePortal.depositEncrypted` with a recipient encrypted inside `data` and a Tempo refund recipient also taken from `data`.
- **Closed access mode.** A Zone in closed access mode requires every successful callback to append a deposit back to the source Zone.

Today a leaked access key scoped to `requestWithdrawal` can drain every account it is authorized on:

| Gap | Today | Effect of a leaked key |
|---|---|---|
| Recipient | TIP-1011 recipient rules apply only to TIP-20 `transfer`, `approve` and `transferWithMemo`, and check only ABI argument 0 | Withdraws to any address |
| Amount | The outbox pulls funds with `transferFrom` on an allowance. TIP-20 charges a key's limit only when there is no spender, so a standing allowance (the Zone docs recommend a maximum approval) is spent without charging the key | Withdraws more than the key's limit (CYCLOPS-2952, CYCLOPS-2798) |
| Returns | A receiver returns change and outputs to an encrypted recipient and a Tempo refund recipient, both read from `data`, which the key holder writes | With `to` pinned to a router, spends a tiny amount and returns the rest, or an Earn output, to itself |

Alternatives considered:

- **TIP-1161 policy contracts.** A policy can check `to`, but it cannot read the encrypted return recipient, cannot track cumulative spend because it is read-only, and per-account policy configuration adds a second write to key setup. TIP-1161 remains the general tool for checks this TIP does not cover.
- **Arbitrary calldata rules in the keychain.** These still cannot see encrypted data, and they widen the keychain's surface beyond the known Zone withdrawal function.
- **Exact approvals instead of a limit charge.** Documenting exact approvals (CYCLOPS-2798 option 3) leaves the bypass open to any account that kept a standing approval.

## Assumptions

- **Receivers check their own destinations.** A recipient rule only moves trust to the listed receiver. A router whose spenders pay any destination, such as a generic `SendSpender`, gives no protection. Key holders list only receivers whose spenders check where funds go.
- **Zone callers are accounts.** Zones run no user contracts, so the outbox's caller is always the signing account. Section 2 depends on this.
- **Fork activation.** Portal, outbox and keychain changes activate together at a Zone hardfork, which follows the matching Tempo fork. Routers that return funds migrate to the new return path after activation; until they do, keys pointed at them stay exposed through returns.
- **Earlier rulings.** ZELLIC-17 and CYCLOPS-2392 ruled that an approval counts as the spend, because a general `transferFrom` cannot tell which key to charge. The outbox only ever debits its caller, so that reason does not apply to it.

---

# Specification

## Overview

Terms:

- **Key holder**: the party holding an access key on a user's Zone account, such as a card issuer.
- **Receiver**: a Tempo contract that receives a callback withdrawal through `onWithdrawalReceived`, such as a Zone router.
- **Return**: funds a receiver sends back to the source Zone during a successful callback.
- **Fallback recipient**: the withdrawal's `zoneFallbackRecipient`, stored on the Zone under its `fallbackNonce` (see Motivation).

Lifecycle for a card spend:

1. At card setup, the user signs one key authorization on the Zone. Its scope allows `requestWithdrawal` only to the issuer's router, with a periodic limit.
2. The key holder signs `requestWithdrawal` to the router for the spend's maximum input. The Zone keychain checks `to` and the fallback recipient (section 1), and the outbox charges the key's limit (section 2).
3. On Tempo, the router pays the spend and approves any change to the portal. The portal queues the change as a bounce-back to the fallback recipient (section 3).
4. The Zone credits the change to the user.

The user authorizes the key and its limit; the protocol enforces both. The key holder chooses amounts and callback data. It cannot choose where funds go: `to` must be on the user's list, and the fallback recipient must be the user.

## Mechanics

### 1. Recipient-bound withdrawals

On Zone chains, `ZoneOutbox.requestWithdrawal` becomes a constrained selector for TIP-1011 recipient rules:

1. A `SelectorRule` with `recipients = [a1, ...]` for `requestWithdrawal` is valid only when `target` is the Zone's `ZoneOutbox`. Otherwise the key authorization is rejected with `InvalidCallScope`, as for other invalid rules.
2. The keychain checks the recipient at ABI argument 1 (`to`) for this selector, instead of argument 0. The call reverts with `CallNotAllowed` unless `to` is in `recipients`.
3. For the same rule, the call reverts with `CallNotAllowed` unless ABI argument 5 (`zoneFallbackRecipient`) equals the account.
4. `recipients = []` keeps today's behavior: any recipient and any fallback.

Both arguments are fixed-size words in the ABI head, so the check needs no decoding of `data` or `revealTo`. On Tempo itself, the selector is not constrained.

### 2. Spending limits apply to withdrawals once

1. `requestWithdrawal` debits `amount` from its caller directly, without an allowance, and burns it, as `burn_at` does for bridges under TIP-1006.
2. When an access key signed the transaction, the debit is charged against that key's `TokenLimit` for `token` and emits `AccessKeySpend`. If the remaining limit is too small, the request reverts before any debit or burn.
3. A withdrawal fee paid by the caller is debited the same way. A sponsor's fee payer that pays the fee keeps using its outbox allowance; it is not the key's account and has no key limit to bypass.
4. Other allowances granted to the outbox are no longer read, so existing approvals become inert. A key that still approves the outbox before withdrawing is charged for the approval and again for the withdrawal, so key holders drop the approve call.

Root-key withdrawals, and keys without limits, are unaffected apart from no longer needing an approval.

### 3. Returns to the fallback recipient

Today a callback either succeeds and keeps everything, or fails and the whole withdrawal bounces back to the fallback recipient. This TIP lets a successful callback return funds through the same bounce-back path:

1. During `onWithdrawalReceived`, a receiver may approve the portal for one amount of one token enabled on the source Zone: change in the withdrawn token, or an output such as Earn shares from a deposit or the asset from a redeem.
2. After the callback succeeds, the portal pulls the approved amount, takes the portal's deposit fee from it, and queues a `WithdrawalBounceBackDeposit` with the withdrawal's `fallbackNonce`, that token and the remaining amount.
3. The return uses the one deposit-queue slot the portal already reserves for each callback (`CALLBACK_DEPOSIT_AVAILABLE`). A callback that returns funds this way cannot also call `depositEncrypted` for the same slot.
4. If the approved amount is below the deposit fee, the callback is treated as failed: its effects roll back and the whole withdrawal bounces back, as today.
5. In closed access mode, the return is the deposit a successful callback must append to the source Zone.
6. On the Zone, the inbox handles the entry like any withdrawal bounce-back: it consumes the fallback nonce and mints to the fallback recipient, or credits the Zone refund registry if the mint reverts.

Receivers that return funds to the source Zone MUST use this path, not `depositEncrypted` with a recipient taken from `data`. Together with section 1, nothing the signer puts in `data` can move funds out of the account, except the spend the receiver itself validates.

## Interfaces

No new functions. Changed behavior:

| Interface | Change |
|---|---|
| `AccountKeychain` (Zone) | Accepts recipient rules for `ZoneOutbox.requestWithdrawal(address,address,uint128,bytes32,uint64,address,bytes,bytes)`; checks argument 1 against `recipients` and argument 5 against the account |
| `ZoneOutbox.requestWithdrawal` | Debits the caller without an allowance and charges the key's limit; fee-payer fees keep the allowance path |
| `ZonePortal` callback delivery | After a successful `onWithdrawalReceived`, pulls one approved token amount and queues it as a `WithdrawalBounceBackDeposit` for the withdrawal's `fallbackNonce` |

Errors reuse `InvalidCallScope` and `CallNotAllowed` from TIP-1011 and the outbox's existing spending-limit error.

# Compatibility

| Integration | What changes |
|---|---|
| Users and wallets | Still one key authorization. A delegated withdrawal scope adds `recipients: [receiver]` to `requestWithdrawal` and no longer needs an `approve(outbox)` rule. Root withdrawals no longer need an approval first; an approval that is still sent is harmless. Wallets can show the receiver as the key's only destination. |
| Key holders | Sign `requestWithdrawal` alone. Callback data carries no encrypted return payload, sequencer key index or Tempo refund recipient. Size the withdrawal as the spend plus the deposit fee and a margin; no bounce-back fee buffer is needed. |
| Zone and Earn routers | Return change or outputs by approving one amount to the portal instead of calling `depositEncrypted`. Routers are immutable, so this ships as a new router deployment. |
| Indexers and APIs | Returns appear as `WithdrawalBounceBack` on Tempo and `WithdrawalBounceBackProcessed` on the Zone for the withdrawal's nonce, not as encrypted deposits. Flows that matched change by deposit queue hash match it by withdrawal instead. |
| Existing keys | Unchanged until re-authorized with a recipient rule. Section 2 applies to every limited key at activation. |
| TIP-1161 | Independent. Policies remain the tool for argument checks this TIP does not cover. |

Open for implementation review: whether any inbox, prover or indexer invariant assumes a bounce-back follows only a failed withdrawal, or carries the withdrawn token.

# Observability

- `AccessKeySpend(account, publicKey, token, amount, remainingLimit)` is emitted for every withdrawal signed by a limited key, answering how much of the key's limit a withdrawal used.
- `WithdrawalBounceBack(queueHash, fallbackNonce, token, amount, depositNumber)` on Tempo and `WithdrawalBounceBackProcessed(zoneFallbackRecipient, token, amount)` or `WithdrawalBounceBackPending` on the Zone record each return. `WithdrawalProcessed` with `success = true` distinguishes a return from a failed withdrawal's bounce-back.

No new events are required.

# Threat Model

The main attack is a leaked key holder's key used to move a user's Zone funds. With this TIP, the key can only withdraw to a listed receiver, up to its limit, and anything returned goes to the user.

| Actor | Controls | Enforcing check | If compromised |
|---|---|---|---|
| Key holder (leaked key) | Amount, memo, gas, callback data | Recipient rule, fallback rule, spending limit, the receiver's own checks | Spends up to the limit through the receiver; returns still reach the user |
| Receiver | What it pays and returns | The fallback-only return path; its own destination checks | A receiver that pays arbitrary destinations voids section 1 for keys that list it |
| Sequencer | Batch ordering and inclusion | Existing proof and queue checks | Unchanged |
| User (root key) | Key scope, limits, revocation | Keychain authorization | Controls the account anyway |

Residual risks:

- A leaked key can still spend up to its limit through the receiver, for example into an issuer's settlement wallet with no card payment behind it. Funds are not stolen, but the user loses them until reconciled.
- Receivers not yet migrated to the return path keep today's exposure through returns.
- A failed return mint parks funds in the Zone refund registry, which the user claims with `claimRefund`.

# Invariants

- A key with a recipient rule on `requestWithdrawal` can only withdraw to a listed recipient, with the account as fallback.
- Every withdrawal debited from a limited key's account reduces that key's remaining limit by exactly the amount debited, whatever outbox allowances exist.
- A withdrawal produces at most one deposit-queue entry on Tempo: a return or a bounce-back.
- Funds a receiver returns are credited only to the withdrawal's fallback recipient, or to its Zone refund entry.

Tests must cover: an unlisted `to`; a fallback other than the account; a withdrawal over the limit with a standing maximum allowance; a key that approves then withdraws; root withdrawals with and without an approval; a sponsored fee; a receiver returning part, all or none of the amount; a return in another enabled token; a return below the deposit fee; a return in closed access mode; and a router spend whose signer-chosen `data` tries to redirect change.
