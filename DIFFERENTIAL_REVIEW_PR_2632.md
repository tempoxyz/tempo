# Differential Review: PR #2632

## Scope / coverage

- Reviewed the current `pull/2632/head` branch as fetched on 2026-03-25.
- Important note: the PR head is currently **48 commits ahead of `main`**, so this is no longer the original small spec-only change described on the PR page.
- Focused review on the highest-risk runtime paths:
  - account-keychain authorization
  - revm transaction validation / execution setup
  - transaction-pool invalidation logic
- I attempted to run focused Rust tests on the PR branch, but the local toolchain is `rustc 1.92.0` while this branch requires `rustc 1.93.0`, so execution coverage is limited to static analysis.

## Findings

### 1. T2 account-key authorization now rejects same-tx root provisioning

**Severity:** High

On T2, `AccountKeychain::authorize_key` now goes through `ensure_admin_caller()`, which rejects admin operations unless `tx_origin` has been seeded and equals `msg_sender`:

- `/tmp/tempo-pr2632/crates/precompiles/src/account_keychain/mod.rs:390-399`

However, the inline `key_authorization` path calls `keychain.authorize_key(*root_account, authorize_call)` during handler-side pre-execution validation **before** `seed_tx_origin()` is run:

- `/tmp/tempo-pr2632/crates/revm/src/handler.rs:972-1026`
- `/tmp/tempo-pr2632/crates/revm/src/handler.rs:727-730` (`seed_tx_origin` only happens later from `validate_against_state_and_deduct_caller`)

That means any post-T2 transaction using inline `key_authorization` (including the same-tx auth+use flow the handler explicitly supports) will start failing with `UnauthorizedCaller`, because `tx_origin` is still zero in this phase.

This looks like a real behavioral regression: the new failed-closed admin check is correct for ordinary runtime calls, but the handler’s internal root-signed provisioning path wasn’t updated to seed `tx_origin` first or to bypass the check for this trusted pre-execution path.

### 2. Sponsored keychain txs are still evicted from the active pool on spending-limit changes

**Severity:** Medium

The paused-pool invalidation logic was updated to preserve **sponsored** keychain transactions when spending-limit updates/spends occur, by checking whether the sender actually paid:

- `/tmp/tempo-pr2632/crates/transaction-pool/src/paused.rs:222-239`

But the main pool’s invalidation path still evicts any matching keychain subject unconditionally for both:

- spending-limit updates: `/tmp/tempo-pr2632/crates/transaction-pool/src/tempo_pool.rs:259-267`
- spending-limit spends: `/tmp/tempo-pr2632/crates/transaction-pool/src/tempo_pool.rs:270-283`

There is no equivalent `sender_paid` guard there. So a sponsored keychain transaction can remain valid semantically, yet still get dropped from the active pool whenever the sender’s spending limit changes or another sender-paid keychain tx consumes that limit.

The new paused-pool tests strongly suggest the intended semantics are “sponsored txs do not consume / depend on the sender’s key spending limit”; the active-pool path is now inconsistent with that rule.

## Overall

I would not approve as-is. The T2 `tx_origin` hardening appears to break inline key authorization, and the sponsored-keychain invalidation fix was only applied to the paused pool, not the active pool.
