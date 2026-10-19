---
name: tempo-rust-style
description: Rust conventions reviewers enforce on tempo, zones, and reth. Use when writing, refactoring, or reviewing Rust in these repos, before opening or updating a PR.
---

# Tempo Rust Style

These are the comments reviewers leave most often. Follow them so they don't have to.

## Scope

- Change only what the task needs. No drive-by fixes, renames, import reshuffles, or formatting churn. Put unrelated work in its own PR.
- Before pushing, read the full diff and revert every hunk the PR description doesn't explain.
- Refactors keep behavior identical: same ordering, gas, errors, and file semantics. If behavior must change, say so in the PR description.
- When wrapping or moving a type, keep existing call sites unchanged (`Deref` or delegating methods).

## Reuse before writing

- Before writing a helper, search the workspace and alloy, reth, revm, and commonware for one that exists.
- Prefer upstream APIs to manual byte handling:
  - `B256::from(U256)`, `U256::from(B256)`, `Address::into_word()`
  - `Log::topic0()`, `Signature::as_bytes()`, `Signature::as_rsy()`
  - `Bytes::from([u8; N])`, `PayloadId::from_str`
  - `alloy_rlp::decode_exact`, `abi_decode_validate`
  - `sol!` for ABI and EIP-712 types, `reth_codecs::Compact` for DB codecs
- Call typed alloy `Provider` methods, never `raw_request` with `serde_json::Value`.
- Retry with alloy's `RetryBackoffLayer`, not a hand-written loop.
- Import constants (addresses, storage slots, chain ids, fork parameters) from the crate that owns them. Derive storage slots from `sol!` or `#[contract]` bindings, never hardcode them.
- When the same logic appears twice, including test wait loops, extract one helper.

## Keep it small

- No helper, wrapper, trait, enum, or type alias with a single call site. Inline it. The one exception is a type alias that replaces `#[allow(clippy::type_complexity)]`.
- Don't add a `foo_with_x` that forwards to `foo`. Generalize `foo`.
- Add code only with a caller in the same PR. This covers `pub` items, fields, accessors, config knobs, CLI flags, RPC methods, cargo features, generics, and extra bounds.
- No caches, interior mutability, or format versioning without a measured need.
- No indirection whose only purpose is test injection.
- Don't re-check an invariant that is already enforced upstream. If correctness depends on it, say where it's enforced in a one-line comment.
- When removing or replacing something, delete everything it leaves behind: always-`None` fields, unused params (don't `_`-prefix them), dead variants and constants, unused Cargo dependencies, stale docs. Never leave commented-out code.

## Comments and docs

- A comment states one non-obvious fact. Don't restate the code or narrate the change.
- Every new `pub` item, trait method, and struct field gets a doc comment. Existing items don't need backfilling. Say what it does, when it is called, what `None`, `false`, or an error means, and any side effects or input contracts such as off-by-one offsets.
- Keep existing comments and TODOs when moving code.
- When behavior changes, update everything that describes it in the same PR: doc comments, `expect` and error-context strings, READMEs, specs, metric names.
- Temporary code gets `// TODO: remove after <fork or feature>`.

## Naming

- Names say what a thing does or holds, including side effects: `*_blocking`, `init` for async constructors that do work, `ensure_*` for assertion helpers.
- Inside a module, name types `Config` and `Error`, not `FooConfig` and `FooError`.
- Generic parameters are descriptive and `T`-prefixed (`TExecutionLayer`).
- Rename an item when its meaning changes. Leave unrelated names alone.
- Don't alias imports with `use X as Y`; it breaks grep. The one exception is a second major version of a crate, as in `rand_08`.
- Don't reuse names of alloy or reth types for different things.

## Errors

- No `unwrap` outside tests. `expect("why")` is only for true invariants; never `expect`, `panic!`, or `unreachable!` on a path that input, a peer, or the network can reach.
- Use typed `thiserror` errors. Never `Result<_, String>` or an early `.to_string()`; carry the source error in the variant. Match the error type the file already uses.
- With eyre, add `.wrap_err("...")` to `?` at boundaries. Use `ok_or_eyre` instead of `ok_or_else(|| eyre!(..))`.
- Never discard a fallible result with `.ok()` or `let _ =`. Ignore only the specific variant you expect.
- Don't log an error and continue when the error is unrecoverable. Don't log an error you also return.
- For gas and index math, use `checked_*` and return an error, not `saturating_*`. Use `try_from` for conversions; `as` only when it can't truncate.

## Types

- Make invalid states unrepresentable. Put variant-specific data inside enum variants, not in correlated `bool`/`Option` fields, and don't use sentinel values such as `0` for "none".
- Use plain `bool`s for independent flags. Don't use `Option<T>` for a value that is always present.
- Use a named struct or newtype instead of a tuple in public or serialized types.
- Put `NonZero*` types (`NZUsize!`, `NZU64!`) on config fields instead of treating `0` as `1` at use sites.
- Enforce invariants when decoding. Strict decoders reject trailing bytes and unknown fields.
- A function that doesn't use `self` is a free function. Logic that belongs to a type goes in its `impl`.
- Bump the version constant whenever a persisted or serialized shape changes.

## Tests

- Every new branch, guard, error path, and access check gets a test in the same PR.
- Assert the exact error or revert selector, not just `is_err()` or `status == false`.
- Assert the property under test, not just that the system eventually converges.
- Assert return values; don't drop them with `let _ =`.
- Bound every wait with a timeout. No unbounded polling loops.
- Keep tests independent with small fixtures, and reuse the crate's existing harness.
- Don't repeat unit coverage in e2e, and don't add tests for trivial behavior.
- Before deleting a test as redundant, show that another test fails when the guarded line breaks.
- Add fuzz or property tests for decoders and state machines.

## Async and observability

- Every wait and sleep is bounded and races the shutdown token. Every queue and retained map has a bound. Spawn tasks on the node's task executor.
- Wrap network awaits in a timeout.
- Put `#[instrument(skip_all, err)]` on fallible async functions. Long-running tasks log inside a root span, and spawned closures enter the parent span.
- Use `error!` for local faults and `warn!` for peer or external faults. Don't log at `info` inside poll loops.
- Add a metric to new network-bound or slow paths. Count skips with a dedicated counter, not by recording zeros.

## Layout and visibility

- Imports go at the top of the file, never inside functions. Don't gate a `use` with `#[cfg(feature)]`; write the full path at the call site instead.
- Use names already imported (`b256!`, `B256`) instead of fully qualified paths.
- Test-only helpers and imports live in `mod tests`, which starts with `use super::*`.
- Keep items `pub(crate)` or private unless another crate uses them. Re-export types that appear in public signatures from the facade crate.
- Order each file as: main type, its `impl`, trait impls, helper types, private functions, `mod tests`.
- Use a type alias instead of `#[allow(clippy::type_complexity)]`, and `#[expect(lint, reason = "...")]` instead of `#[allow]`.

## Performance

- Don't clone large values (transaction envs, logs, state) to read them. Borrow them, `take` them, or share them through `Arc`.
- Use entry APIs instead of a lookup followed by an insert. Don't read the same storage slot or DB value twice.
- Do one-time setup in constructors, not per transaction.
- Cap any length that comes from untrusted input before `Vec::with_capacity` or a loop.
- Perf PRs include before/after numbers. Use benches, not `#[ignore]` tests.

## Dependencies and CI

- Inherit dependencies from the workspace with minimal features. Check that each touched crate builds on its own, since workspace dependencies default to no features. Run `zepter` after editing `Cargo.toml`.
- Never pull `std` or reth into `no_std` crates; use `core` and `alloc`.
- Don't add a second major version of a crate.
- When crates or configs move, update the CI path filters.

## Tempo hardforks

- Gate any change to the state transition function (precompile output, errors, gas, system calls, bytecode) behind the next unreleased hardfork. Never change the behavior of an active fork.
- When refactoring a shared path, keep pre-fork operation order and gas identical.
- Use the same fork everywhere: the TIP's `protocolVersion`, `is_tN` checks, and tests.
- Don't add checks for an older fork on code that only runs after a newer one.
- Put fork-dependent values on `TempoHardfork` methods, and check activation through the chainspec (`is_tN_active_at`).
- Keep at least one test on the previous fork. Cover new-fork behavior with a new test rather than editing the old one.

## Tempo precompiles and specs

- Access precompile state through the storage API (`StorageCtx`, `.read()`, `mapping_slot`), and emit events with `self.emit_event()`.
- Use `TempoPrecompileError::Fatal` only for invariant violations. Failures a user can trigger revert.
- TIPs are prose requirements. Don't include implementation code, alerts, or test listings.
- TIPs justify every constant and limit, and state failure, overflow, and range behavior explicitly.
- When an interface changes, update the TIP, `invariants.md`, the Solidity reference implementation, and the Rust precompile in the same PR.
- Keep the Solidity and Rust storage layouts identical.

## Zones

- Zones launched after T6 and have no hardforks of their own. Don't gate zone code or tests on a fork, and don't pass `spec` through helpers.
- Reuse the constants, ABIs, and helpers that tempo exports instead of redefining them.

## PR description

- One to three sentences: the bug or need, then what changed. Call out on-disk or datadir breaks.
